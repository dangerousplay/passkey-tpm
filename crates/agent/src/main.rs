//! `passkey-tpm-agent`: per-user virtual FIDO security key backed by the passkey-tpm broker.
//!
//! The device exists only while this user has an active session on a local seat: after a
//! user switch the hidraw node's ACL moves to the new seat user, so the agent removes the
//! device while its user is in the background (HARD-01) and brings it back afterwards.
#![allow(clippy::print_stderr)]

use std::process::ExitCode;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use passkey_tpm_agent::{Effect, Hid};
use passkey_tpm_transport_uhid::{fido_device_params, UhidDevice, UhidEvent, UhidWriter};
use passkey_tpm_uv::seat::{self, Logind, SessionPolicy};
use tokio::sync::mpsc;
use zbus::Connection;

const BUS_NAME: &str = "io.github.dangerousplay.PasskeyTpm1";
const OBJECT_PATH: &str = "/io/github/dangerousplay/PasskeyTpm1";
const TICK: Duration = Duration::from_millis(100);
/// Generous bound on a broker call: the broker's fingerprint timeout is 30 s.
const BROKER_TIMEOUT: Duration = Duration::from_secs(45);
const STATUS_OTHER: u8 = 0x7F;
/// Re-check of the seat state in case a logind signal was missed.
const SEAT_POLL: Duration = Duration::from_secs(2);

enum Input {
    Output(Vec<u8>),
    Reply(Vec<u8>),
    DeviceGone,
    /// Whether this user is in the foreground on a seat (sent on every check).
    Seat(bool),
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    // A failing OS RNG leaves zeros, which `Hid` rejects and retries.
    let _ = getrandom::fill(&mut b);
    u32::from_ne_bytes(b)
}

async fn ctap(bus: &Connection, request: Vec<u8>) -> zbus::Result<Vec<u8>> {
    let reply = bus
        .call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "Ctap",
            &(request,),
        )
        .await?;
    reply.body().deserialize::<Vec<u8>>()
}

async fn cancel(bus: &Connection) -> zbus::Result<()> {
    bus.call_method(Some(BUS_NAME), OBJECT_PATH, Some(BUS_NAME), "Cancel", &())
        .await
        .map(|_| ())
}

fn prompt(rp: String) {
    // Informational only: the agent runs in the user's session and can be spoofed by
    // same-user malware (docs/threat-model.md, "prompt spoofing").
    tokio::task::spawn_blocking(move || {
        let _ = notify_rust::Notification::new()
            .appname("passkey-tpm")
            .summary("Touch the fingerprint reader")
            .body(&format!("to continue with {rp}"))
            .icon("fingerprint")
            .timeout(notify_rust::Timeout::Milliseconds(30_000))
            .show();
    });
}

/// The uid this agent runs as (owner of its own `/proc` entry).
fn own_uid() -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid())
}

/// Reports this user's seat state at start, after every logind change signal and every
/// [`SEAT_POLL`].
fn watch_seat(bus: Connection, uid: u32, tx: mpsc::UnboundedSender<Input>) {
    tokio::spawn(async move {
        let policy = Logind::new(bus.clone());
        let mut changes = match seat::changes(&bus).await {
            Ok(stream) => Some(stream),
            Err(e) => {
                eprintln!("cannot watch logind sessions, polling only: {e}");
                None
            }
        };
        let mut poll = tokio::time::interval(SEAT_POLL);
        loop {
            if tx.send(Input::Seat(policy.is_active(uid).await)).is_err() {
                return;
            }
            let signal = async {
                match changes.as_mut() {
                    Some(stream) => stream.next().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = poll.tick() => {}
                Some(()) = signal => {}
            }
        }
    });
}

/// Opens `/dev/uhid`, creates the device and starts the thread that forwards its events.
fn open_device(tx: &mpsc::UnboundedSender<Input>) -> std::io::Result<UhidWriter> {
    let mut device = UhidDevice::create(&fido_device_params())?;
    let writer = device.try_clone_writer()?;
    let reader_tx = tx.clone();
    std::thread::spawn(move || loop {
        match device.read_event() {
            Ok(UhidEvent::Output(data)) => {
                if reader_tx.send(Input::Output(data)).is_err() {
                    return;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                eprintln!("ignoring uhid event: {e}");
            }
            Err(e) => {
                eprintln!("uhid read failed: {e}");
                let _ = reader_tx.send(Input::DeviceGone);
                return;
            }
        }
    });
    Ok(writer)
}

fn apply(
    effects: Vec<Effect>,
    writer: Option<&UhidWriter>,
    bus: &Connection,
    tx: &mpsc::UnboundedSender<Input>,
) {
    for effect in effects {
        match effect {
            Effect::Write(reports) => {
                // No device (user in the background): nobody to answer.
                let Some(writer) = writer else { continue };
                for report in reports {
                    if let Err(e) = writer.write_input(&report) {
                        eprintln!("uhid write failed: {e}");
                    }
                }
            }
            Effect::Broker(request) => {
                let bus = bus.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let response =
                        match tokio::time::timeout(BROKER_TIMEOUT, ctap(&bus, request)).await {
                            Ok(Ok(r)) => r,
                            Ok(Err(e)) => {
                                eprintln!("broker call failed: {e}");
                                vec![STATUS_OTHER]
                            }
                            Err(_) => vec![STATUS_OTHER],
                        };
                    let _ = tx.send(Input::Reply(response));
                });
            }
            Effect::Cancel => {
                let bus = bus.clone();
                tokio::spawn(async move {
                    if let Err(e) = cancel(&bus).await {
                        eprintln!("broker cancel failed: {e}");
                    }
                });
            }
            Effect::Prompt(rp) => prompt(rp),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let bus = match Connection::system().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot connect to the system bus: {e}");
            return ExitCode::FAILURE;
        }
    };
    let uid = match own_uid() {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("cannot determine the agent's uid: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    watch_seat(bus.clone(), uid, tx.clone());

    // `/dev/uhid` stays open for the agent's lifetime once opened; `present` tracks whether
    // the HID device currently exists on it.
    let mut writer: Option<UhidWriter> = None;
    let mut present = false;
    let start = Instant::now();
    let now_ms = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut hid = Hid::new(random_u32);
    let mut tick = tokio::time::interval(TICK);
    eprintln!("passkey-tpm-agent ready");
    loop {
        let link = if present { writer.as_ref() } else { None };
        tokio::select! {
            input = rx.recv() => match input {
                Some(Input::Output(data)) if present => apply(hid.on_output(&data, now_ms()), link, &bus, &tx),
                Some(Input::Output(_)) => {}
                Some(Input::Reply(response)) => apply(hid.on_broker_reply(&response), link, &bus, &tx),
                Some(Input::Seat(true)) if !present => {
                    let result = match &writer {
                        Some(w) => w.recreate(&fido_device_params()),
                        None => open_device(&tx).map(|w| writer = Some(w)),
                    };
                    match result {
                        Ok(()) => {
                            present = true;
                            eprintln!("session active: virtual key added");
                        }
                        Err(e) => {
                            eprintln!("cannot create the virtual FIDO device via /dev/uhid: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
                Some(Input::Seat(false)) if present => {
                    apply(hid.reset(), None, &bus, &tx);
                    present = false;
                    if let Some(Err(e)) = writer.as_ref().map(UhidWriter::remove_device) {
                        // Can't guarantee the device is gone: stop, which closes the handle.
                        eprintln!("cannot remove the virtual key: {e}");
                        return ExitCode::FAILURE;
                    }
                    eprintln!("session in the background: virtual key removed");
                }
                Some(Input::Seat(_)) => {}
                Some(Input::DeviceGone) | None => return ExitCode::FAILURE,
            },
            _ = tick.tick() => apply(hid.on_tick(now_ms()), link, &bus, &tx),
            _ = tokio::signal::ctrl_c() => return ExitCode::SUCCESS,
        }
    }
}

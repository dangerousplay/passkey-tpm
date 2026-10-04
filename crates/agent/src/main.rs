//! `passkey-tpm-agent`: per-user virtual FIDO security key backed by the passkey-tpm broker.
#![allow(clippy::print_stderr)]

use std::process::ExitCode;
use std::time::{Duration, Instant};

use passkey_tpm_agent::{Effect, Hid};
use passkey_tpm_transport_uhid::{fido_device_params, UhidDevice, UhidEvent, UhidWriter};
use tokio::sync::mpsc;
use zbus::Connection;

const BUS_NAME: &str = "io.github.dangerousplay.PasskeyTpm1";
const OBJECT_PATH: &str = "/io/github/dangerousplay/PasskeyTpm1";
const TICK: Duration = Duration::from_millis(100);
/// Generous bound on a broker call: the broker's fingerprint timeout is 30 s.
const BROKER_TIMEOUT: Duration = Duration::from_secs(45);
const STATUS_OTHER: u8 = 0x7F;

enum Input {
    Output(Vec<u8>),
    Reply(Vec<u8>),
    DeviceGone,
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

fn apply(
    effects: Vec<Effect>,
    writer: &UhidWriter,
    bus: &Connection,
    tx: &mpsc::UnboundedSender<Input>,
) {
    for effect in effects {
        match effect {
            Effect::Write(reports) => {
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
    let mut device = match UhidDevice::create(&fido_device_params()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot create the virtual FIDO device via /dev/uhid: {e}");
            return ExitCode::FAILURE;
        }
    };
    let writer = match device.try_clone_writer() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot clone the uhid handle: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
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

    let start = Instant::now();
    let now_ms = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut hid = Hid::new(random_u32);
    let mut tick = tokio::time::interval(TICK);
    eprintln!("passkey-tpm-agent ready");
    loop {
        tokio::select! {
            input = rx.recv() => match input {
                Some(Input::Output(data)) => apply(hid.on_output(&data, now_ms()), &writer, &bus, &tx),
                Some(Input::Reply(response)) => apply(hid.on_broker_reply(&response), &writer, &bus, &tx),
                Some(Input::DeviceGone) | None => return ExitCode::FAILURE,
            },
            _ = tick.tick() => apply(hid.on_tick(now_ms()), &writer, &bus, &tx),
            _ = tokio::signal::ctrl_c() => return ExitCode::SUCCESS,
        }
    }
}

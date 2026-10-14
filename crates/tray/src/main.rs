//! `passkey-tpm-tray`: StatusNotifierItem with passkey-tpm status and fingerprint enrollment.
//!
//! Menu callbacks only send a [`Command`]; the loop in [`main`] runs probes and enrollment
//! as tasks and pushes state back through the `ksni` handle.
#![allow(clippy::print_stderr)]

use std::process::ExitCode;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::Duration;

use ksni::menu::StandardItem;
use ksni::{Category, Icon, MenuItem, Status, ToolTip, TrayMethods};
use passkey_tpm_tray::{
    dialog, finger_label, fingerprint_pixmap, health_colour, pin, probe, EnrollTracker, Health,
    Message, PinAction, PinState, Snapshot,
};
use passkey_tpm_uv::fprintd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zbus::Connection;

/// Periodic status refresh.
const REFRESH: Duration = Duration::from_secs(10);
/// Bound on one enrollment, including the polkit dialog.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for fprintd cleanup when quitting mid-enrollment.
const QUIT_GRACE: Duration = Duration::from_secs(3);
/// Pixmap sizes offered to the tray host.
const ICON_SIZES: [u32; 4] = [16, 22, 32, 48];

#[derive(Debug)]
enum Command {
    Refresh,
    Enroll(&'static str),
    CancelEnroll,
    EnrollDone,
    Pin(PinAction),
    PinDone,
    Quit,
}

#[derive(Debug)]
struct TrayApp {
    snapshot: Snapshot,
    /// The finger being enrolled.
    enrolling: Option<&'static str>,
    tx: mpsc::UnboundedSender<Command>,
}

impl TrayApp {
    fn icons(&self) -> Vec<Icon> {
        let rgb = health_colour(&self.snapshot.health());
        ICON_SIZES
            .into_iter()
            .map(|size| {
                let p = fingerprint_pixmap(size, rgb);
                let side = i32::try_from(p.size).unwrap_or(0);
                Icon {
                    width: side,
                    height: side,
                    data: p.data,
                }
            })
            .collect()
    }

    fn send(&self, command: Command) {
        let _ = self.tx.send(command);
    }
}

fn info_item(label: String) -> MenuItem<TrayApp> {
    StandardItem {
        label,
        enabled: false,
        ..Default::default()
    }
    .into()
}

impl ksni::Tray for TrayApp {
    fn id(&self) -> String {
        "passkey-tpm".into()
    }

    fn title(&self) -> String {
        "passkey-tpm".into()
    }

    fn category(&self) -> Category {
        Category::Hardware
    }

    fn status(&self) -> Status {
        match self.snapshot.health() {
            Health::Problem(_) => Status::NeedsAttention,
            Health::Ready | Health::Checking => Status::Active,
        }
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        self.icons()
    }

    fn attention_icon_pixmap(&self) -> Vec<Icon> {
        self.icons()
    }

    fn tool_tip(&self) -> ToolTip {
        let description = match (self.enrolling, self.snapshot.health()) {
            (Some(finger), _) => format!("Enrolling your {}", finger_label(finger)),
            (None, Health::Ready) => "Ready".to_owned(),
            (None, Health::Checking) => "Checking…".to_owned(),
            (None, Health::Problem(p)) => p,
        };
        ToolTip {
            title: "passkey-tpm".into(),
            description,
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(Command::Refresh);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items = vec![
            info_item(self.snapshot.reader_line()),
            info_item(self.snapshot.broker_line()),
            info_item(self.snapshot.key_line()),
            info_item(self.snapshot.pin_line()),
            MenuItem::Separator,
        ];
        match (self.enrolling, self.snapshot.enroll_target()) {
            (Some(finger), _) => items.push(
                StandardItem {
                    label: format!("Cancel enrollment ({})", finger_label(finger)),
                    icon_name: "process-stop".into(),
                    activate: Box::new(|t: &mut Self| t.send(Command::CancelEnroll)),
                    ..Default::default()
                }
                .into(),
            ),
            (None, Some(Some(finger))) => items.push(
                StandardItem {
                    label: "Enroll new fingerprint".into(),
                    icon_name: "list-add".into(),
                    activate: Box::new(move |t: &mut Self| t.send(Command::Enroll(finger))),
                    ..Default::default()
                }
                .into(),
            ),
            (None, Some(None)) => items.push(info_item("All fingers enrolled".into())),
            (None, None) => {}
        }
        if let Some(action) = self.snapshot.pin_action() {
            let label = match action {
                PinAction::Set => "Set PIN…",
                PinAction::Change => "Change PIN…",
            };
            items.push(
                StandardItem {
                    label: label.into(),
                    icon_name: "dialog-password".into(),
                    activate: Box::new(move |t: &mut Self| t.send(Command::Pin(action))),
                    ..Default::default()
                }
                .into(),
            );
        }
        items.extend([
            StandardItem {
                label: "Refresh".into(),
                icon_name: "view-refresh".into(),
                activate: Box::new(|t: &mut Self| t.send(Command::Refresh)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|t: &mut Self| t.send(Command::Quit)),
                ..Default::default()
            }
            .into(),
        ]);
        items
    }
}

/// A desktop notification. `replace` reuses the previous notification of the same
/// enrollment so progress updates in place.
#[derive(Debug)]
struct Note {
    message: Message,
    replace: bool,
}

/// Shows notifications in order on one blocking thread.
fn notifier() -> std_mpsc::Sender<Note> {
    let (tx, rx) = std_mpsc::channel::<Note>();
    std::thread::spawn(move || {
        let mut last = None;
        for note in rx {
            let (summary, body) = note.message;
            let mut n = notify_rust::Notification::new();
            n.appname("passkey-tpm")
                .summary(&summary)
                .body(&body)
                .icon("fingerprint")
                .timeout(notify_rust::Timeout::Milliseconds(10_000));
            if let (true, Some(id)) = (note.replace, last) {
                n.id(id);
            }
            match n.show() {
                Ok(handle) => last = Some(handle.id()),
                Err(e) => eprintln!("cannot show notification: {e}"),
            }
        }
    });
    tx
}

/// `full` also asks the broker whether a PIN is set; periodic refreshes reuse the known
/// answer (each broker request is an audit line in its journal).
fn spawn_refresh(
    system: Option<Connection>,
    session: Option<Connection>,
    handle: ksni::Handle<TrayApp>,
    busy: Arc<tokio::sync::Mutex<()>>,
    full: bool,
) {
    tokio::spawn(async move {
        // One refresh at a time. A periodic one during another refresh is covered by it; a
        // full one waits so it sees the latest PIN state.
        let _guard = if full {
            busy.lock().await
        } else {
            let Ok(guard) = busy.try_lock() else {
                return;
            };
            guard
        };
        let known_pin = if full {
            None
        } else {
            handle
                .update(|t| t.snapshot.pin.clone())
                .await
                .filter(|p| matches!(p, PinState::Set | PinState::NotSet))
        };
        let snapshot = probe::snapshot(system.as_ref(), session.as_ref(), known_pin).await;
        handle.update(|t| t.snapshot = snapshot).await;
    });
}

/// Asks for the PIN(s) and runs setPIN or changePIN through the broker.
fn spawn_pin(
    system: Connection,
    action: PinAction,
    notes: std_mpsc::Sender<Note>,
    tx: mpsc::UnboundedSender<Command>,
) {
    tokio::spawn(async move {
        if let Some(message) = pin_flow(&system, action).await {
            let _ = notes.send(Note {
                message,
                replace: false,
            });
        }
        let _ = tx.send(Command::PinDone);
    });
}

/// The notification to show after a PIN action, `None` if the user cancelled.
async fn pin_flow(system: &Connection, action: PinAction) -> Option<Message> {
    let change = action == PinAction::Change;
    let failed = |body: String| {
        Some((
            if change {
                "PIN not changed"
            } else {
                "PIN not set"
            }
            .to_owned(),
            body,
        ))
    };
    let entry = match dialog::ask(change).await {
        Ok(e) => e,
        Err(dialog::DialogError::Cancelled) => return None,
        Err(dialog::DialogError::NoHelper) => {
            return failed(
                "Install zenity or kdialog to enter a PIN from the tray, or set it from your \
                 browser's security key settings."
                    .to_owned(),
            );
        }
        Err(dialog::DialogError::Failed(e)) => {
            return failed(format!("The PIN dialog failed: {e}"));
        }
    };
    if let Err(problem) = pin::check_new_pin(&entry.new, &entry.confirm) {
        return failed(problem);
    }
    let result = if change {
        pin::change(system, &entry.current, &entry.new).await
    } else {
        pin::set(system, &entry.new).await
    };
    match result {
        Ok(()) => Some((
            if change { "PIN changed" } else { "PIN set" }.to_owned(),
            "Websites will ask for this PIN when you use a passkey.".to_owned(),
        )),
        Err(e) => failed(e.describe()),
    }
}

fn spawn_enroll(
    system: Connection,
    finger: &'static str,
    cancel: CancellationToken,
    notes: std_mpsc::Sender<Note>,
    tx: mpsc::UnboundedSender<Command>,
) {
    tokio::spawn(async move {
        let mut tracker = EnrollTracker::new(finger);
        let mut first = true;
        let result = fprintd::enroll(&system, finger, ENROLL_TIMEOUT, cancel, |progress| {
            let _ = notes.send(Note {
                message: tracker.progress(&progress),
                replace: !first,
            });
            first = false;
        })
        .await;
        let _ = notes.send(Note {
            message: tracker.result(&result),
            replace: !first,
        });
        let _ = tx.send(Command::EnrollDone);
    });
}

#[tokio::main]
async fn main() -> ExitCode {
    let system = match Connection::system().await {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("cannot connect to the system bus: {e}");
            None
        }
    };
    let session = match Connection::session().await {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("cannot connect to the session bus: {e}");
            None
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let app = TrayApp {
        snapshot: Snapshot::default(),
        enrolling: None,
        tx: tx.clone(),
    };
    // Autostart can run before the panel: wait for a StatusNotifierWatcher instead of exiting.
    let handle = match app.assume_sni_available(true).spawn().await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cannot register the tray icon: {e}");
            return ExitCode::FAILURE;
        }
    };

    let notes = notifier();
    let busy = Arc::new(tokio::sync::Mutex::new(()));
    let refresh = |full: bool| {
        spawn_refresh(
            system.clone(),
            session.clone(),
            handle.clone(),
            busy.clone(),
            full,
        );
    };
    let mut cancel: Option<CancellationToken> = None;
    let mut pin_busy = false;
    let mut tick = tokio::time::interval(REFRESH);
    loop {
        tokio::select! {
            _ = tick.tick() => refresh(false),
            command = rx.recv() => match command {
                Some(Command::Refresh) => refresh(true),
                Some(Command::Enroll(finger)) => {
                    let Some(system) = system.clone() else { continue };
                    if cancel.is_some() {
                        continue;
                    }
                    let token = CancellationToken::new();
                    cancel = Some(token.clone());
                    handle.update(|t| t.enrolling = Some(finger)).await;
                    spawn_enroll(system, finger, token, notes.clone(), tx.clone());
                }
                Some(Command::CancelEnroll) => {
                    if let Some(token) = &cancel {
                        token.cancel();
                    }
                }
                Some(Command::EnrollDone) => {
                    cancel = None;
                    handle.update(|t| t.enrolling = None).await;
                    refresh(true);
                }
                Some(Command::Pin(action)) => {
                    let Some(system) = system.clone() else { continue };
                    if pin_busy {
                        continue;
                    }
                    pin_busy = true;
                    spawn_pin(system, action, notes.clone(), tx.clone());
                }
                Some(Command::PinDone) => {
                    pin_busy = false;
                    refresh(true);
                }
                Some(Command::Quit) | None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    // Let a running enrollment send EnrollStop and Release before exiting.
    if let Some(token) = cancel {
        token.cancel();
        let done = async {
            while let Some(command) = rx.recv().await {
                if matches!(command, Command::EnrollDone) {
                    return;
                }
            }
        };
        let _ = tokio::time::timeout(QUIT_GRACE, done).await;
    }
    handle.shutdown().await;
    ExitCode::SUCCESS
}

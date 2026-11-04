//! The tray item and the notification client against mock panel and notification servers
//! on a private bus.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use passkey_tpm_desktop::notify::{Answer, Notification, Notifier};
use passkey_tpm_desktop::tray::{self, Category, Icon, MenuItem, StandardItem, Status, ToolTip};
use passkey_tpm_testkit::bus::PrivateBus;
use zbus::object_server::SignalEmitter;
use zbus::{Connection, OwnedVariant};

const STEP: Duration = Duration::from_secs(5);

// ----------------------------------------------------------------------------- tray icon

#[derive(Debug)]
struct Demo {
    clicks: Arc<Mutex<Vec<&'static str>>>,
    ready: bool,
}

impl tray::Tray for Demo {
    type Action = &'static str;

    fn id(&self) -> String {
        "demo".into()
    }
    fn title(&self) -> String {
        "Demo".into()
    }
    fn category(&self) -> Category {
        Category::Hardware
    }
    fn status(&self) -> Status {
        if self.ready {
            Status::Active
        } else {
            Status::NeedsAttention
        }
    }
    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![Icon {
            width: 1,
            height: 1,
            data: vec![255, 1, 2, 3],
        }]
    }
    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            title: "Demo".into(),
            description: if self.ready { "Ready" } else { "Problem" }.into(),
        }
    }
    fn menu(&self) -> Vec<MenuItem<Self::Action>> {
        vec![
            StandardItem::info(if self.ready { "ok" } else { "broken" }).into(),
            MenuItem::Separator,
            StandardItem::new("Refresh", "view-refresh", "refresh").into(),
        ]
    }
    fn on_action(&mut self, action: &'static str) {
        self.clicks.lock().unwrap().push(action);
        self.ready = true;
    }
}

/// A panel: records the items that register.
#[derive(Default)]
struct MockWatcher {
    items: Arc<Mutex<Vec<String>>>,
}

#[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
impl MockWatcher {
    fn register_status_notifier_item(&self, service: String) {
        self.items.lock().unwrap().push(service);
    }
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + STEP;
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

type Layout = (i32, HashMap<String, OwnedVariant>, Vec<OwnedVariant>);

#[tokio::test(flavor = "multi_thread")]
async fn tray_registers_serves_its_menu_and_reports_changes() {
    let bus = PrivateBus::start();
    let app = bus.connect().await;
    let host = bus.connect().await;
    let clicks = Arc::new(Mutex::new(Vec::new()));
    let handle = tray::spawn(
        &app,
        Demo {
            clicks: clicks.clone(),
            ready: false,
        },
    )
    .await
    .unwrap();

    // The panel starts after the item: the item registers when the watcher appears.
    let registered = Arc::new(Mutex::new(Vec::new()));
    host.object_server()
        .at(
            "/StatusNotifierWatcher",
            MockWatcher {
                items: registered.clone(),
            },
        )
        .await
        .unwrap();
    host.request_name("org.kde.StatusNotifierWatcher")
        .await
        .unwrap();
    wait_until("registration", || {
        registered
            .lock()
            .unwrap()
            .iter()
            .any(|n| n == handle.name())
    })
    .await;

    let item = zbus::Proxy::new(
        &host,
        handle.name().to_owned(),
        "/StatusNotifierItem",
        "org.kde.StatusNotifierItem",
    )
    .await
    .unwrap();
    let status: String = item.get_property("Status").await.unwrap();
    assert_eq!(status, "NeedsAttention");
    let icons: Vec<(i32, i32, Vec<u8>)> = item.get_property("IconPixmap").await.unwrap();
    assert_eq!(icons, [(1, 1, vec![255, 1, 2, 3])]);
    let menu_path: zbus::OwnedObjectPath = item.get_property("Menu").await.unwrap();

    let menu = zbus::Proxy::new(
        &host,
        handle.name().to_owned(),
        menu_path,
        "com.canonical.dbusmenu",
    )
    .await
    .unwrap();
    let (revision, layout): (u32, Layout) = menu
        .call("GetLayout", &(0i32, -1i32, Vec::<String>::new()))
        .await
        .unwrap();
    assert_eq!(layout.0, 0, "root");
    assert_eq!(layout.2.len(), 3);
    let first = zbus::wire::Structure::try_from(layout.2[0].try_clone().unwrap()).unwrap();
    let (id, props, _): Layout = first.try_into().unwrap();
    assert_eq!(id, 1);
    assert_eq!(
        String::try_from(props["label"].try_clone().unwrap()).unwrap(),
        "broken"
    );
    assert!(!bool::try_from(props["enabled"].try_clone().unwrap()).unwrap());

    // Clicking "Refresh" runs the action; the changed status and menu are announced.
    let mut status_signals = item.receive_signal("NewStatus").await.unwrap();
    let mut layout_signals = menu.receive_signal("LayoutUpdated").await.unwrap();
    let () = menu
        .call("Event", &(3i32, "clicked", zbus::Variant::from(""), 0u32))
        .await
        .unwrap();
    assert_eq!(*clicks.lock().unwrap(), ["refresh"]);
    let signal = tokio::time::timeout(STEP, status_signals.next())
        .await
        .unwrap()
        .unwrap();
    let (status,): (String,) = signal.body().deserialize().unwrap();
    assert_eq!(status, "Active");
    let signal = tokio::time::timeout(STEP, layout_signals.next())
        .await
        .unwrap()
        .unwrap();
    let (new_revision, parent): (u32, i32) = signal.body().deserialize().unwrap();
    assert_eq!((new_revision, parent), (revision + 1, 0));

    // A disabled entry does nothing; an unknown one is an error.
    let () = menu
        .call("Event", &(1i32, "clicked", zbus::Variant::from(""), 0u32))
        .await
        .unwrap();
    assert_eq!(clicks.lock().unwrap().len(), 1);
    assert!(menu
        .call::<_, _, ()>("Event", &(9i32, "clicked", zbus::Variant::from(""), 0u32))
        .await
        .is_err());

    // update() with no visible change emits nothing; shutdown removes the objects.
    handle.update(|t| t.ready = true).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), status_signals.next())
            .await
            .is_err(),
        "no change, no signal"
    );
    let name = handle.name().to_owned();
    handle.shutdown().await;
    let props = zbus::fdo::PropertiesProxy::builder(&host)
        .destination(name)
        .path("/StatusNotifierItem")
        .build()
        .await;
    // The name is released, so building the proxy or reading through it fails.
    let gone = match props {
        Err(_) => true,
        Ok(p) => p
            .get("org.kde.StatusNotifierItem".try_into().unwrap(), "Status")
            .await
            .is_err(),
    };
    assert!(gone, "item still served after shutdown");
}

// --------------------------------------------------------------------------- notifications

/// `(replaces_id, summary, actions, expire_timeout)` of every Notify call (and closes).
type Shown = Arc<Mutex<Vec<(u32, String, Vec<String>, i32)>>>;

/// A notification server that answers the second notification it gets with `answer`.
struct MockNotifications {
    shown: Shown,
    next: u32,
    answer: Option<&'static str>,
}

#[zbus::interface(name = "org.freedesktop.Notifications")]
impl MockNotifications {
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &mut self,
        _app_name: String,
        replaces_id: u32,
        _app_icon: String,
        summary: String,
        _body: String,
        actions: Vec<String>,
        _hints: HashMap<String, OwnedVariant>,
        expire_timeout: i32,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> u32 {
        let id = if replaces_id == 0 {
            self.next += 1;
            self.next
        } else {
            replaces_id
        };
        self.shown
            .lock()
            .unwrap()
            .push((replaces_id, summary, actions, expire_timeout));
        // Answer right away, before the client could subscribe after the call returns.
        if let Some(key) = self.answer {
            let emitter = emitter.to_owned();
            tokio::spawn(async move {
                Self::action_invoked(&emitter, id, key).await.unwrap();
                Self::notification_closed(&emitter, id, 2).await.unwrap();
            });
        }
        id
    }

    fn close_notification(&self, id: u32) {
        self.shown
            .lock()
            .unwrap()
            .push((id, "closed".into(), Vec::new(), 0));
    }

    #[zbus(signal)]
    async fn action_invoked(emitter: &SignalEmitter<'_>, id: u32, key: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn notification_closed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        reason: u32,
    ) -> zbus::Result<()>;
}

async fn notification_server(
    bus: &PrivateBus,
    answer: Option<&'static str>,
) -> (Connection, Shown) {
    let server = bus.connect().await;
    let shown = Arc::new(Mutex::new(Vec::new()));
    server
        .object_server()
        .at(
            "/org/freedesktop/Notifications",
            MockNotifications {
                shown: shown.clone(),
                next: 0,
                answer,
            },
        )
        .await
        .unwrap();
    server
        .request_name("org.freedesktop.Notifications")
        .await
        .unwrap();
    (server, shown)
}

#[tokio::test(flavor = "multi_thread")]
async fn notifications_show_replace_close_and_answer() {
    let bus = PrivateBus::start();
    let (_server, shown) = notification_server(&bus, Some("allow")).await;
    let client = bus.connect().await;
    let notifier = Notifier::new(&client).await.unwrap();

    let n = Notification::new("passkey-tpm", "Allow passkey-tpm?", "example.com")
        .action("allow", "Allow")
        .action("deny", "Deny")
        .timeout_ms(30_000);
    let (id, answer) = notifier.ask(&n).await.unwrap();
    assert_eq!(
        tokio::time::timeout(STEP, answer).await.unwrap(),
        Answer::Action("allow".into()),
        "the action wins over the close that follows it"
    );
    let replaced = notifier
        .show(&Notification::new("passkey-tpm", "Done", "").replaces(Some(id)))
        .await
        .unwrap();
    assert_eq!(replaced, id);
    notifier.close(id).await.unwrap();

    let log = shown.lock().unwrap().clone();
    assert_eq!(
        log[0],
        (
            0,
            "Allow passkey-tpm?".into(),
            vec!["allow".into(), "Allow".into(), "deny".into(), "Deny".into()],
            30_000
        )
    );
    assert_eq!(
        (log[1].0, log[1].3),
        (id, -1),
        "replaces, server default timeout"
    );
    assert_eq!(log[2], (id, "closed".into(), Vec::new(), 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn notification_closed_without_action() {
    let bus = PrivateBus::start();
    let (server, _shown) = notification_server(&bus, None).await;
    let client = bus.connect().await;
    let notifier = Notifier::new(&client).await.unwrap();
    let (id, answer) = notifier
        .ask(&Notification::new("passkey-tpm", "Hi", ""))
        .await
        .unwrap();
    let emitter = SignalEmitter::new(&server, "/org/freedesktop/Notifications").unwrap();
    // Another notification's close is not ours.
    MockNotifications::notification_closed(&emitter, id + 1, 1)
        .await
        .unwrap();
    MockNotifications::notification_closed(&emitter, id, 1)
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(STEP, answer).await.unwrap(),
        Answer::Closed
    );
}

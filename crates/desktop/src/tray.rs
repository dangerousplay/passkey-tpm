//! A StatusNotifierItem (freedesktop/KDE spec) with a flat `com.canonical.dbusmenu` menu.
//!
//! Implement [`Tray`], [`spawn`] it on the session bus and change it through
//! [`Handle::update`]: after every change the item emits only the `New*` and
//! `LayoutUpdated` signals whose content actually changed. The item registers with
//! `org.kde.StatusNotifierWatcher` and again whenever a watcher (the panel) starts, so the
//! icon appears even when the program starts before the panel.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
use tokio::sync::Mutex;
use zbus::object_server::SignalEmitter;
use zbus::{fdo, Connection, OwnedObjectPath, OwnedVariant, Variant};

const ITEM_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const WATCHER: &str = "org.kde.StatusNotifierWatcher";
const WATCHER_PATH: &str = "/StatusNotifierWatcher";
/// dbusmenu id of the (invisible) root item; entries are numbered from 1.
const ROOT: i32 = 0;

/// An ARGB32 image in network byte order, as StatusNotifierItem expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icon {
    pub width: i32,
    pub height: i32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    ApplicationStatus,
    Communications,
    SystemServices,
    Hardware,
}

impl Category {
    fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationStatus => "ApplicationStatus",
            Self::Communications => "Communications",
            Self::SystemServices => "SystemServices",
            Self::Hardware => "Hardware",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Passive,
    Active,
    NeedsAttention,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "Passive",
            Self::Active => "Active",
            Self::NeedsAttention => "NeedsAttention",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolTip {
    pub title: String,
    pub description: String,
}

/// A clickable (or, with `action: None` or `enabled: false`, informational) menu entry.
#[derive(Debug, Clone)]
pub struct StandardItem<A> {
    pub label: String,
    /// Freedesktop icon name, empty for none.
    pub icon_name: String,
    pub enabled: bool,
    /// Passed to [`Tray::on_action`] when the entry is clicked.
    pub action: Option<A>,
}

impl<A> StandardItem<A> {
    /// An enabled entry that triggers `action`.
    pub fn new(label: impl Into<String>, icon_name: &str, action: A) -> Self {
        Self {
            label: label.into(),
            icon_name: icon_name.to_owned(),
            enabled: true,
            action: Some(action),
        }
    }

    /// A greyed-out line of text.
    pub fn info(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            icon_name: String::new(),
            enabled: false,
            action: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MenuItem<A> {
    Separator,
    Standard(StandardItem<A>),
}

impl<A> From<StandardItem<A>> for MenuItem<A> {
    fn from(item: StandardItem<A>) -> Self {
        Self::Standard(item)
    }
}

/// What the tray shows. Every method is called with the state locked, so keep them cheap.
pub trait Tray: Send + 'static {
    /// Sent back to [`Tray::on_action`] when a menu entry is clicked.
    type Action: Clone + Send + Sync + 'static;

    fn id(&self) -> String;
    fn title(&self) -> String;
    fn category(&self) -> Category;
    fn status(&self) -> Status;
    fn icon_pixmap(&self) -> Vec<Icon>;
    fn attention_icon_pixmap(&self) -> Vec<Icon> {
        self.icon_pixmap()
    }
    fn tool_tip(&self) -> ToolTip;
    fn menu(&self) -> Vec<MenuItem<Self::Action>>;
    /// Primary click on the icon.
    fn activate(&mut self) {}
    fn on_action(&mut self, action: Self::Action);
}

type Pixmaps = Vec<(i32, i32, Vec<u8>)>;

fn pixmaps(icons: Vec<Icon>) -> Pixmaps {
    icons
        .into_iter()
        .map(|i| (i.width, i.height, i.data))
        .collect()
}

/// The visible properties of one menu entry, for change detection and dbusmenu.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Separator,
    Standard {
        label: String,
        icon_name: String,
        enabled: bool,
    },
}

impl Entry {
    fn of<A>(item: &MenuItem<A>) -> Self {
        match item {
            MenuItem::Separator => Self::Separator,
            MenuItem::Standard(s) => Self::Standard {
                label: s.label.clone(),
                icon_name: s.icon_name.clone(),
                enabled: s.enabled,
            },
        }
    }

    /// dbusmenu properties (only the non-default ones, as the spec suggests).
    fn properties(&self) -> Vec<(&'static str, Variant<'static>)> {
        match self {
            Self::Separator => vec![("type", Variant::from("separator"))],
            Self::Standard {
                label,
                icon_name,
                enabled,
            } => {
                let mut props = vec![("label", Variant::from(label.clone()))];
                if !icon_name.is_empty() {
                    props.push(("icon-name", Variant::from(icon_name.clone())));
                }
                if !enabled {
                    props.push(("enabled", Variant::from(false)));
                }
                props
            }
        }
    }
}

/// Everything a host can see, rendered from the [`Tray`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rendered {
    title: String,
    status: Status,
    icon: Pixmaps,
    attention: Pixmaps,
    tool_tip: ToolTip,
    entries: Vec<Entry>,
}

impl Rendered {
    fn of<T: Tray>(tray: &T, menu: &[MenuItem<T::Action>]) -> Self {
        Self {
            title: tray.title(),
            status: tray.status(),
            icon: pixmaps(tray.icon_pixmap()),
            attention: pixmaps(tray.attention_icon_pixmap()),
            tool_tip: tray.tool_tip(),
            entries: menu.iter().map(Entry::of).collect(),
        }
    }
}

struct State<T: Tray> {
    tray: T,
    /// The menu hosts were last told about: dbusmenu ids are indexes into it, plus one.
    menu: Vec<MenuItem<T::Action>>,
    shown: Rendered,
    revision: u32,
}

struct Shared<T: Tray> {
    conn: Connection,
    state: Mutex<State<T>>,
}

impl<T: Tray> Shared<T> {
    /// Re-renders after a change and emits the signals for what changed.
    async fn refresh(&self, state: &mut State<T>) {
        let menu = state.tray.menu();
        let now = Rendered::of(&state.tray, &menu);
        let before = std::mem::replace(&mut state.shown, now.clone());
        state.menu = menu;
        if now.entries != before.entries {
            state.revision = state.revision.wrapping_add(1);
        }
        // A failed signal needs no retry: hosts re-read everything when they (re)appear.
        let _ = self.announce(&before, &now, state.revision).await;
    }

    async fn announce(&self, before: &Rendered, now: &Rendered, revision: u32) -> zbus::Result<()> {
        let item = SignalEmitter::new(&self.conn, ITEM_PATH)?;
        if now.title != before.title {
            Item::<T>::new_title(&item).await?;
        }
        if now.icon != before.icon {
            Item::<T>::new_icon(&item).await?;
        }
        if now.attention != before.attention {
            Item::<T>::new_attention_icon(&item).await?;
        }
        if now.tool_tip != before.tool_tip {
            Item::<T>::new_tool_tip(&item).await?;
        }
        if now.status != before.status {
            Item::<T>::new_status(&item, now.status.as_str()).await?;
        }
        if now.entries != before.entries {
            let menu = SignalEmitter::new(&self.conn, MENU_PATH)?;
            Menu::<T>::layout_updated(&menu, revision, ROOT).await?;
        }
        Ok(())
    }

    /// Runs `f` on the tray and announces the result.
    async fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut state = self.state.lock().await;
        let result = f(&mut state.tray);
        self.refresh(&mut state).await;
        result
    }
}

// ------------------------------------------------------------------- StatusNotifierItem

struct Item<T: Tray> {
    shared: Arc<Shared<T>>,
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl<T: Tray> Item<T> {
    async fn activate(&self, _x: i32, _y: i32) {
        self.shared.with(T::activate).await;
    }

    async fn secondary_activate(&self, _x: i32, _y: i32) {}

    /// The host shows the menu from the `Menu` property; nothing to do here.
    async fn context_menu(&self, _x: i32, _y: i32) {}

    async fn scroll(&self, _delta: i32, _orientation: String) {}

    #[zbus(property)]
    async fn category(&self) -> String {
        self.shared
            .state
            .lock()
            .await
            .tray
            .category()
            .as_str()
            .to_owned()
    }

    #[zbus(property)]
    async fn id(&self) -> String {
        self.shared.state.lock().await.tray.id()
    }

    #[zbus(property)]
    async fn title(&self) -> String {
        self.shared.state.lock().await.shown.title.clone()
    }

    #[zbus(property)]
    async fn status(&self) -> String {
        self.shared
            .state
            .lock()
            .await
            .shown
            .status
            .as_str()
            .to_owned()
    }

    #[zbus(property)]
    fn window_id(&self) -> i32 {
        0
    }

    #[zbus(property)]
    fn icon_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    async fn icon_pixmap(&self) -> Pixmaps {
        self.shared.state.lock().await.shown.icon.clone()
    }

    #[zbus(property)]
    fn overlay_icon_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Pixmaps {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_icon_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    async fn attention_icon_pixmap(&self) -> Pixmaps {
        self.shared.state.lock().await.shown.attention.clone()
    }

    #[zbus(property)]
    fn attention_movie_name(&self) -> String {
        String::new()
    }

    /// `(icon name, icon pixmaps, title, description)`.
    #[zbus(property)]
    async fn tool_tip(&self) -> (String, Pixmaps, String, String) {
        let tip = self.shared.state.lock().await.shown.tool_tip.clone();
        (String::new(), Vec::new(), tip.title, tip.description)
    }

    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from(MENU_PATH).unwrap_or_default()
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> String {
        String::new()
    }

    #[zbus(signal)]
    async fn new_title(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_attention_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_tool_tip(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_status(emitter: &SignalEmitter<'_>, status: &str) -> zbus::Result<()>;
}

// ------------------------------------------------------------------------------ dbusmenu

/// `(id, properties, children)`: a dbusmenu layout node.
type Layout = (i32, HashMap<String, OwnedVariant>, Vec<OwnedVariant>);

fn owned(v: Variant<'_>) -> OwnedVariant {
    // Only plain values (strings, booleans, structures of them) are converted here, which
    // never carry file descriptors, so this cannot fail.
    OwnedVariant::try_from(v).unwrap_or_else(|_| OwnedVariant::from(false))
}

/// `names` empty means every property.
fn filtered(entry: &Entry, names: &[String]) -> HashMap<String, OwnedVariant> {
    entry
        .properties()
        .into_iter()
        .filter(|(name, _)| names.is_empty() || names.iter().any(|n| n == name))
        .map(|(name, value)| (name.to_owned(), owned(value)))
        .collect()
}

fn id_of(index: usize) -> i32 {
    i32::try_from(index).map_or(i32::MAX, |i| i.saturating_add(1))
}

fn index_of(id: i32) -> Option<usize> {
    usize::try_from(id.checked_sub(1)?).ok()
}

fn root_layout(entries: &[Entry], depth: i32, names: &[String]) -> Layout {
    let children = if depth == 0 {
        Vec::new()
    } else {
        entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let node = zbus::wire::Structure::from((
                    id_of(i),
                    filtered(entry, names),
                    Vec::<OwnedVariant>::new(),
                ));
                owned(Variant::from(node))
            })
            .collect()
    };
    let mut props = HashMap::new();
    props.insert(
        "children-display".to_owned(),
        owned(Variant::from("submenu")),
    );
    (ROOT, props, children)
}

struct Menu<T: Tray> {
    shared: Arc<Shared<T>>,
}

impl<T: Tray> Menu<T> {
    /// Handles a `clicked` event on entry `id`; false if there is no such entry.
    async fn click(&self, id: i32) -> bool {
        let mut state = self.shared.state.lock().await;
        let action = match index_of(id).and_then(|i| state.menu.get(i)) {
            Some(MenuItem::Standard(item)) if item.enabled => item.action.clone(),
            Some(_) => None,
            None => return false,
        };
        if let Some(action) = action {
            state.tray.on_action(action);
            self.shared.refresh(&mut state).await;
        }
        true
    }
}

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl<T: Tray> Menu<T> {
    async fn get_layout(
        &self,
        parent_id: i32,
        recursion_depth: i32,
        property_names: Vec<String>,
    ) -> fdo::Result<(u32, Layout)> {
        let state = self.shared.state.lock().await;
        let layout = if parent_id == ROOT {
            root_layout(&state.shown.entries, recursion_depth, &property_names)
        } else {
            let entry = index_of(parent_id)
                .and_then(|i| state.shown.entries.get(i))
                .ok_or_else(|| fdo::Error::InvalidArgs(format!("no menu item {parent_id}")))?;
            (parent_id, filtered(entry, &property_names), Vec::new())
        };
        Ok((state.revision, layout))
    }

    async fn get_group_properties(
        &self,
        ids: Vec<i32>,
        property_names: Vec<String>,
    ) -> Vec<(i32, HashMap<String, OwnedVariant>)> {
        let state = self.shared.state.lock().await;
        let entries = &state.shown.entries;
        let all: Vec<i32> = (0..entries.len()).map(id_of).collect();
        let wanted = if ids.is_empty() { all } else { ids };
        wanted
            .into_iter()
            .filter_map(|id| {
                let entry = entries.get(index_of(id)?)?;
                Some((id, filtered(entry, &property_names)))
            })
            .collect()
    }

    async fn get_property(&self, id: i32, name: String) -> fdo::Result<OwnedVariant> {
        let state = self.shared.state.lock().await;
        let entry = index_of(id)
            .and_then(|i| state.shown.entries.get(i))
            .ok_or_else(|| fdo::Error::InvalidArgs(format!("no menu item {id}")))?;
        filtered(entry, std::slice::from_ref(&name))
            .remove(&name)
            .ok_or_else(|| fdo::Error::InvalidArgs(format!("no property {name}")))
    }

    async fn event(
        &self,
        id: i32,
        event_id: String,
        _data: OwnedVariant,
        _timestamp: u32,
    ) -> fdo::Result<()> {
        if event_id != "clicked" {
            return Ok(());
        }
        if self.click(id).await {
            Ok(())
        } else {
            Err(fdo::Error::InvalidArgs(format!("no menu item {id}")))
        }
    }

    /// Returns the ids that were not found.
    async fn event_group(&self, events: Vec<(i32, String, OwnedVariant, u32)>) -> Vec<i32> {
        let mut missing = Vec::new();
        for (id, event_id, _, _) in events {
            if event_id == "clicked" && !self.click(id).await {
                missing.push(id);
            }
        }
        missing
    }

    /// The menu is always up to date: no update needed before showing it.
    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        (Vec::new(), Vec::new())
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }

    #[zbus(property)]
    fn text_direction(&self) -> String {
        "ltr".to_owned()
    }

    #[zbus(property)]
    fn status(&self) -> String {
        "normal".to_owned()
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(signal)]
    async fn layout_updated(
        emitter: &SignalEmitter<'_>,
        revision: u32,
        parent: i32,
    ) -> zbus::Result<()>;
}

// ------------------------------------------------------------------------------- running

#[zbus::proxy(
    interface = "org.kde.StatusNotifierWatcher",
    default_service = "org.kde.StatusNotifierWatcher",
    default_path = "/StatusNotifierWatcher"
)]
trait Watcher {
    fn register_status_notifier_item(&self, service: &str) -> zbus::Result<()>;
}

/// A running tray icon.
pub struct Handle<T: Tray> {
    shared: Arc<Shared<T>>,
    name: String,
    watcher: Arc<tokio::task::JoinHandle<()>>,
}

impl<T: Tray> std::fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle").field("name", &self.name).finish()
    }
}

impl<T: Tray> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            name: self.name.clone(),
            watcher: self.watcher.clone(),
        }
    }
}

impl<T: Tray> Handle<T> {
    /// Changes the tray and tells hosts what changed.
    pub async fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        self.shared.with(f).await
    }

    /// The bus name the item is registered under.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Removes the icon (for every clone of this handle).
    pub async fn shutdown(self) {
        self.watcher.abort();
        let server = self.shared.conn.object_server();
        let _ = server.remove::<Item<T>, _>(ITEM_PATH).await;
        let _ = server.remove::<Menu<T>, _>(MENU_PATH).await;
        let _ = self.shared.conn.release_name(self.name.as_str()).await;
    }
}

async fn register(conn: &Connection, name: &str) -> zbus::Result<()> {
    WatcherProxy::builder(conn)
        .path(WATCHER_PATH)
        .build()
        .await?
        .register_status_notifier_item(name)
        .await
}

/// Serves `tray` on `session` and registers it with the panel's watcher, now if one runs and
/// whenever one starts later.
///
/// # Errors
/// If the bus name can't be owned or the objects can't be served.
pub async fn spawn<T: Tray>(session: &Connection, tray: T) -> zbus::Result<Handle<T>> {
    let menu = tray.menu();
    let shown = Rendered::of(&tray, &menu);
    let shared = Arc::new(Shared {
        conn: session.clone(),
        state: Mutex::new(State {
            tray,
            menu,
            shown,
            revision: 1,
        }),
    });
    let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
    session.request_name(name.as_str()).await?;
    let server = session.object_server();
    server
        .at(
            ITEM_PATH,
            Item {
                shared: shared.clone(),
            },
        )
        .await?;
    server
        .at(
            MENU_PATH,
            Menu {
                shared: shared.clone(),
            },
        )
        .await?;

    let dbus = fdo::DBusProxy::new(session).await?;
    let mut owners = dbus
        .receive_name_owner_changed_with_args(&[(0, WATCHER)])
        .await?;
    let conn = session.clone();
    let item_name = name.clone();
    let watcher = tokio::spawn(async move {
        // No watcher yet is normal (autostart before the panel): wait for one.
        let _ = register(&conn, &item_name).await;
        while let Some(change) = owners.next().await {
            let started = change.args().is_ok_and(|a| a.new_owner.as_ref().is_some());
            if started {
                let _ = register(&conn, &item_name).await;
            }
        }
    });
    Ok(Handle {
        shared,
        name,
        watcher: Arc::new(watcher),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_ids_are_indexes_plus_one() {
        assert_eq!(id_of(0), 1);
        assert_eq!(index_of(1), Some(0));
        assert_eq!(index_of(ROOT), None);
        assert_eq!(index_of(-3), None);
    }

    #[test]
    fn entries_carry_only_non_default_properties() {
        let info = Entry::of(&MenuItem::<()>::from(StandardItem::info("Reader: ok")));
        let names: Vec<&str> = info.properties().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["label", "enabled"]);
        let sep = Entry::of(&MenuItem::<()>::Separator);
        assert_eq!(filtered(&sep, &[]).len(), 1);
        let item = Entry::of(&MenuItem::from(StandardItem::new(
            "Quit",
            "application-exit",
            (),
        )));
        let only_label = filtered(&item, &["label".to_owned()]);
        assert_eq!(only_label.keys().collect::<Vec<_>>(), ["label"]);
    }

    #[test]
    fn root_layout_depth() {
        let entries = vec![Entry::Separator, Entry::Separator];
        assert_eq!(root_layout(&entries, -1, &[]).2.len(), 2);
        assert!(root_layout(&entries, 0, &[]).2.is_empty());
    }
}

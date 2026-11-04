//! Client for the freedesktop Notifications service (Desktop Notifications Specification
//! 1.2) on the session bus.

use std::collections::HashMap;

use futures_util::StreamExt;
use zbus::Connection;

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, zbus::Variant<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// A notification to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub app_name: String,
    pub icon: String,
    pub summary: String,
    pub body: String,
    /// `(key, label)` buttons.
    pub actions: Vec<(String, String)>,
    /// Expiry in milliseconds; `None` lets the server decide.
    pub timeout_ms: Option<u32>,
    /// Replace this earlier notification in place instead of showing a new one.
    pub replaces: Option<u32>,
}

impl Notification {
    #[must_use]
    pub fn new(app_name: &str, summary: &str, body: &str) -> Self {
        Self {
            app_name: app_name.to_owned(),
            icon: String::new(),
            summary: summary.to_owned(),
            body: body.to_owned(),
            actions: Vec::new(),
            timeout_ms: None,
            replaces: None,
        }
    }

    #[must_use]
    pub fn icon(mut self, icon: &str) -> Self {
        icon.clone_into(&mut self.icon);
        self
    }

    #[must_use]
    pub fn action(mut self, key: &str, label: &str) -> Self {
        self.actions.push((key.to_owned(), label.to_owned()));
        self
    }

    #[must_use]
    pub fn timeout_ms(mut self, ms: u32) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    #[must_use]
    pub fn replaces(mut self, id: Option<u32>) -> Self {
        self.replaces = id;
        self
    }
}

/// How a notification shown with [`Notifier::ask`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The user picked this action key (`"default"` is a click on the notification itself).
    Action(String),
    /// Dismissed, expired or closed without an action.
    Closed,
}

/// A connection to the notification server.
#[derive(Debug, Clone)]
pub struct Notifier {
    proxy: NotificationsProxy<'static>,
}

impl Notifier {
    /// # Errors
    /// If the proxy can't be created on `session`.
    pub async fn new(session: &Connection) -> zbus::Result<Self> {
        Ok(Self {
            proxy: NotificationsProxy::new(session).await?,
        })
    }

    /// Shows `n` and returns its id (pass it to [`Notification::replaces`] to update it).
    ///
    /// # Errors
    /// If the server can't be reached or refuses the notification.
    pub async fn show(&self, n: &Notification) -> zbus::Result<u32> {
        let actions: Vec<&str> = n
            .actions
            .iter()
            .flat_map(|(key, label)| [key.as_str(), label.as_str()])
            .collect();
        let timeout = n
            .timeout_ms
            .map_or(-1, |ms| i32::try_from(ms).unwrap_or(i32::MAX));
        self.proxy
            .notify(
                &n.app_name,
                n.replaces.unwrap_or(0),
                &n.icon,
                &n.summary,
                &n.body,
                &actions,
                HashMap::new(),
                timeout,
            )
            .await
    }

    /// Closes notification `id` (no error if it is already gone).
    ///
    /// # Errors
    /// If the server can't be reached.
    pub async fn close(&self, id: u32) -> zbus::Result<()> {
        self.proxy.close_notification(id).await
    }

    /// Shows `n` and returns its id and a future that resolves when the user answers or the
    /// notification closes. The signals are subscribed before the notification exists, so
    /// a fast answer is never missed.
    ///
    /// # Errors
    /// If the signals can't be subscribed or the notification can't be shown.
    pub async fn ask(
        &self,
        n: &Notification,
    ) -> zbus::Result<(
        u32,
        impl std::future::Future<Output = Answer> + Send + 'static,
    )> {
        let mut actions = self.proxy.receive_action_invoked().await?;
        let mut closed = self.proxy.receive_notification_closed().await?;
        let id = self.show(n).await?;
        let answer = async move {
            loop {
                // The server sends ActionInvoked before NotificationClosed: look at actions
                // first so a click is never reported as a close.
                tokio::select! {
                    biased;
                    Some(signal) = actions.next() => {
                        if let Ok(args) = signal.args() {
                            if args.id == id {
                                return Answer::Action(args.action_key);
                            }
                        }
                    }
                    Some(signal) = closed.next() => {
                        if signal.args().is_ok_and(|args| args.id == id) {
                            return Answer::Closed;
                        }
                    }
                    else => return Answer::Closed,
                }
            }
        };
        Ok((id, answer))
    }
}

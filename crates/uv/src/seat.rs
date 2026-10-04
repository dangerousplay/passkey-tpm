//! Seat-session check: is a user in the foreground on a local seat (HARD-01)?
//!
//! The virtual FIDO device's hidraw node is tagged `uaccess`, so its ACL follows the active
//! seat user. After a fast user switch, user B could open user A's device and the broker
//! would see A's agent (A's uid) on the bus. The broker refuses requests for users without
//! an active seat session, and the agent removes its device while its user is in the
//! background (which also invalidates hidraw descriptors opened earlier).
//!
//! The agent runs under `user@.service`, outside any login session, so the check is by uid
//! (`ListSessions`), not by caller PID.

use std::future::Future;
use std::pin::Pin;

use futures_util::{Stream, StreamExt};
use zbus::message::Type;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, MatchRule, MessageStream};

const LOGIND: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";

/// Decides whether a user may use the authenticator right now.
pub trait SessionPolicy: Send + Sync {
    /// `true` if `uid` has an active session on a local seat. Errors must answer `false`.
    fn is_active<'a>(&'a self, uid: u32) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// [`SessionPolicy`] backed by systemd-logind on the system bus.
#[derive(Debug, Clone)]
pub struct Logind {
    conn: Connection,
}

impl Logind {
    #[must_use]
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn active_seat_session(&self, uid: u32) -> zbus::Result<bool> {
        // a(susso): session id, uid, user name, seat id, object path.
        let reply = self
            .conn
            .call_method(
                Some(LOGIND),
                MANAGER_PATH,
                Some(MANAGER_IFACE),
                "ListSessions",
                &(),
            )
            .await?;
        let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> =
            reply.body().deserialize()?;
        for (_, session_uid, _, seat, path) in sessions {
            // Sessions without a seat (SSH, cron) are never "in front of" a device.
            if session_uid != uid || seat.is_empty() {
                continue;
            }
            let proxy = zbus::fdo::PropertiesProxy::builder(&self.conn)
                .destination(LOGIND)?
                .path(path)?
                .build()
                .await?;
            let active = proxy.get(SESSION_IFACE.try_into()?, "Active").await?;
            if bool::try_from(active).unwrap_or(false) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl SessionPolicy for Logind {
    fn is_active<'a>(&'a self, uid: u32) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match self.active_seat_session(uid).await {
                Ok(active) => active,
                Err(e) => {
                    // Fail closed: without logind we can't tell who is at the seat.
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("logind session check failed for uid={uid}: {e}");
                    }
                    false
                }
            }
        })
    }
}

/// Yields after every logind signal that can change who is at a seat: a session was added
/// or removed, or a session property (such as `Active`) changed. Callers re-check with
/// [`SessionPolicy::is_active`]; the stream carries no state itself.
///
/// # Errors
/// If the match rules can't be added on `conn`.
pub async fn changes(conn: &Connection) -> zbus::Result<impl Stream<Item = ()> + Unpin> {
    let properties = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(LOGIND)?
        .interface("org.freedesktop.DBus.Properties")?
        .member("PropertiesChanged")?
        .arg(0, SESSION_IFACE)?
        .build();
    let manager = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(LOGIND)?
        .path(MANAGER_PATH)?
        .interface(MANAGER_IFACE)?
        .build();
    let properties = MessageStream::for_match_rule(properties, conn, None).await?;
    let manager = MessageStream::for_match_rule(manager, conn, None).await?;
    Ok(futures_util::stream::select(properties, manager).map(|_| ()))
}

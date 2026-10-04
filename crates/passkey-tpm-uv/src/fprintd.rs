//! fprintd D-Bus client.
//!
//! Interface reference: fprintd's introspection files
//! `src/net.reactivated.Fprint.Manager.xml` and `src/net.reactivated.Fprint.Device.xml`
//! (<https://gitlab.freedesktop.org/libfprint/fprintd>).
//!
//! # Security
//!
//! [`verify`] binds the whole operation to a single fprintd instance: it resolves the unique
//! bus name that currently owns `net.reactivated.Fprint`, sends every method call to that
//! unique name and accepts a `VerifyStatus` signal only when its header sender is that unique
//! name and its path is the claimed device. Unique names are never reused by the bus, so
//! another client (or a restarted fprintd that did not see our `Claim`) can't forge a match.
//! Only the literal status `verify-match` with `done = true` yields [`UvResult::Match`].

use std::future::Future;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zbus::message::Type as MessageType;
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, MatchRule, Message, MessageStream};

/// Well-known bus name of fprintd.
pub const SERVICE: &str = "net.reactivated.Fprint";
/// Object path of the fprintd manager.
pub const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
/// Manager interface name.
pub const MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
/// Device interface name.
pub const DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";
/// D-Bus error returned when the user has no enrolled fingerprints.
pub const ERR_NO_ENROLLED_PRINTS: &str = "net.reactivated.Fprint.Error.NoEnrolledPrints";

/// Upper bound for each cleanup call (`VerifyStop`, `Release`) so cleanup can't hang.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Outcome of a fingerprint verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UvResult {
    /// fprintd reported `verify-match` (done) for the user.
    Match,
    /// fprintd reported `verify-no-match` (done).
    NoMatch,
    /// The caller cancelled the verification.
    Cancelled,
    /// No final result arrived before the timeout.
    TimedOut,
    /// fprintd or the reader is unavailable, or reported an error.
    Unavailable(String),
}

/// What a single `VerifyStatus` signal means for the verification loop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    /// Keep waiting for another signal.
    Continue,
    /// Stop with this result.
    Final(UvResult),
}

/// Maps a `VerifyStatus(result, done)` pair to the next step.
///
/// Only `verify-match` with `done = true` is a match. Retry-type statuses (and a non-final
/// no-match, should fprintd allow retries internally) keep waiting.
fn classify(result: &str, done: bool) -> Status {
    match result {
        "verify-match" if done => Status::Final(UvResult::Match),
        "verify-no-match" if done => Status::Final(UvResult::NoMatch),
        "verify-disconnected" | "verify-unknown-error" => {
            Status::Final(UvResult::Unavailable(result.to_owned()))
        }
        _ if done => Status::Final(UvResult::Unavailable(format!(
            "unexpected final status {result:?}"
        ))),
        _ => Status::Continue,
    }
}

/// Returns `true` only if a signal comes from the fprintd instance we talk to and from the
/// claimed device.
fn signal_is_trusted(msg: &Message, owner: &str, device_path: &str) -> bool {
    let header = msg.header();
    let sender_ok = header.sender().is_some_and(|s| s.as_str() == owner);
    let path_ok = header.path().is_some_and(|p| p.as_str() == device_path);
    let iface_ok = header
        .interface()
        .is_some_and(|i| i.as_str() == DEVICE_IFACE);
    let member_ok = header
        .member()
        .is_some_and(|m| m.as_str() == "VerifyStatus");
    msg.message_type() == MessageType::Signal && sender_ok && path_ok && iface_ok && member_ok
}

/// Tracks which device actions may need undoing.
///
/// The flags are set *before* the corresponding call is sent, so a call interrupted by cancel
/// or timeout is still undone (errors from the undo are ignored).
#[derive(Debug, Default)]
struct Session {
    owner: Option<String>,
    device: Option<OwnedObjectPath>,
    claim_sent: bool,
    verify_sent: bool,
}

impl Session {
    async fn cleanup(&self, conn: &Connection) {
        let (Some(owner), Some(device)) = (&self.owner, &self.device) else {
            return;
        };
        if self.verify_sent {
            let _ = tokio::time::timeout(
                CLEANUP_TIMEOUT,
                call_device(conn, owner, device, "VerifyStop", &()),
            )
            .await;
        }
        if self.claim_sent {
            let _ = tokio::time::timeout(
                CLEANUP_TIMEOUT,
                call_device(conn, owner, device, "Release", &()),
            )
            .await;
        }
    }
}

async fn call_device<B>(
    conn: &Connection,
    owner: &str,
    device: &OwnedObjectPath,
    method: &str,
    body: &B,
) -> zbus::Result<Message>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    conn.call_method(
        Some(owner),
        device.as_str(),
        Some(DEVICE_IFACE),
        method,
        body,
    )
    .await
}

/// Resolves the unique name currently owning [`SERVICE`].
async fn name_owner(conn: &Connection) -> zbus::Result<String> {
    let reply = conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetNameOwner",
            &(SERVICE,),
        )
        .await?;
    reply.body().deserialize::<String>()
}

/// Asks the manager (at the given owner) for the default device path.
async fn default_device(conn: &Connection, owner: &str) -> zbus::Result<OwnedObjectPath> {
    let reply = conn
        .call_method(
            Some(owner),
            MANAGER_PATH,
            Some(MANAGER_IFACE),
            "GetDefaultDevice",
            &(),
        )
        .await?;
    reply.body().deserialize::<OwnedObjectPath>()
}

fn unavailable(step: &str, err: &zbus::Error) -> UvResult {
    UvResult::Unavailable(format!("{step}: {err}"))
}

/// Verifies a fingerprint for `username` on fprintd's default device.
///
/// Sequence: `GetNameOwner(net.reactivated.Fprint)`, `GetDefaultDevice`, `Claim(username)`,
/// subscribe to `VerifyStatus`, `VerifyStart("any")`, then wait for a final status.
/// `VerifyStop` (if started) and `Release` (if claimed) are always sent before returning,
/// including on cancel, timeout and errors.
///
/// `timeout` bounds the whole operation (including the D-Bus calls before the scan).
/// Any failure talking to fprintd is reported as [`UvResult::Unavailable`].
pub async fn verify(
    conn: &Connection,
    username: &str,
    timeout: Duration,
    cancel: CancellationToken,
) -> UvResult {
    let deadline = Instant::now() + timeout;
    let mut session = Session::default();
    let result = run_bounded(&cancel, deadline, run(conn, username, &mut session)).await;
    session.cleanup(conn).await;
    result
}

/// Races `fut` against cancellation and the deadline. Cancellation wins ties.
async fn run_bounded(
    cancel: &CancellationToken,
    deadline: Instant,
    fut: impl Future<Output = UvResult>,
) -> UvResult {
    tokio::select! {
        biased;
        () = cancel.cancelled() => UvResult::Cancelled,
        () = tokio::time::sleep_until(deadline) => UvResult::TimedOut,
        r = fut => r,
    }
}

async fn run(conn: &Connection, username: &str, session: &mut Session) -> UvResult {
    let owner = match name_owner(conn).await {
        Ok(o) => o,
        Err(e) => return unavailable("GetNameOwner", &e),
    };
    session.owner = Some(owner.clone());

    let device = match default_device(conn, &owner).await {
        Ok(d) => d,
        Err(e) => return unavailable("GetDefaultDevice", &e),
    };
    session.device = Some(device.clone());

    session.claim_sent = true;
    if let Err(e) = call_device(conn, &owner, &device, "Claim", &(username,)).await {
        return unavailable("Claim", &e);
    }

    // Subscribe before VerifyStart so no status can be missed. AddMatch completes before
    // `for_match_rule` returns.
    let mut stream = match subscribe(conn, &owner, &device).await {
        Ok(s) => s,
        Err(e) => return unavailable("AddMatch", &e),
    };

    session.verify_sent = true;
    if let Err(e) = call_device(conn, &owner, &device, "VerifyStart", &("any",)).await {
        return unavailable("VerifyStart", &e);
    }

    while let Some(item) = stream.next().await {
        let Ok(msg) = item else {
            continue;
        };
        if !signal_is_trusted(&msg, &owner, device.as_str()) {
            continue;
        }
        let Ok((result, done)) = msg.body().deserialize::<(String, bool)>() else {
            continue;
        };
        if let Status::Final(r) = classify(&result, done) {
            return r;
        }
    }
    UvResult::Unavailable("D-Bus connection closed".to_owned())
}

async fn subscribe(
    conn: &Connection,
    owner: &str,
    device: &OwnedObjectPath,
) -> zbus::Result<MessageStream> {
    let rule = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .sender(owner)?
        .path(device.as_str())?
        .interface(DEVICE_IFACE)?
        .member("VerifyStatus")?
        .build();
    MessageStream::for_match_rule(rule, conn, None).await
}

/// Reports whether `username` has at least one fingerprint enrolled on the default device.
///
/// # Errors
///
/// Returns a description if fprintd can't be reached or reports an error other than
/// `NoEnrolledPrints` (which maps to `Ok(false)`).
pub async fn has_enrolled(conn: &Connection, username: &str) -> Result<bool, String> {
    let owner = name_owner(conn)
        .await
        .map_err(|e| format!("GetNameOwner: {e}"))?;
    let device = default_device(conn, &owner)
        .await
        .map_err(|e| format!("GetDefaultDevice: {e}"))?;
    match call_device(conn, &owner, &device, "ListEnrolledFingers", &(username,)).await {
        Ok(reply) => reply
            .body()
            .deserialize::<Vec<String>>()
            .map(|fingers| !fingers.is_empty())
            .map_err(|e| format!("ListEnrolledFingers reply: {e}")),
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == ERR_NO_ENROLLED_PRINTS => {
            Ok(false)
        }
        Err(e) => Err(format!("ListEnrolledFingers: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_final_match_is_match() {
        assert_eq!(
            classify("verify-match", true),
            Status::Final(UvResult::Match)
        );
        assert_eq!(classify("verify-match", false), Status::Continue);
        assert_eq!(
            classify("verify-no-match", true),
            Status::Final(UvResult::NoMatch)
        );
        assert_eq!(classify("verify-no-match", false), Status::Continue);
        for retry in [
            "verify-retry-scan",
            "verify-swipe-too-short",
            "verify-finger-not-centered",
            "verify-remove-and-retry",
            "verify-too-fast",
        ] {
            assert_eq!(classify(retry, false), Status::Continue, "{retry}");
        }
        for err in ["verify-disconnected", "verify-unknown-error"] {
            assert!(matches!(
                classify(err, false),
                Status::Final(UvResult::Unavailable(_))
            ));
            assert!(matches!(
                classify(err, true),
                Status::Final(UvResult::Unavailable(_))
            ));
        }
        assert!(matches!(
            classify("VERIFY-MATCH", true),
            Status::Final(UvResult::Unavailable(_))
        ));
        assert!(matches!(
            classify("verify-match ", true),
            Status::Final(UvResult::Unavailable(_))
        ));
        assert_eq!(classify("something-new", false), Status::Continue);
    }

    fn signal(sender: Option<&str>, path: &str, iface: &str, member: &str) -> Message {
        let mut b = Message::signal(path, iface, member).unwrap();
        if let Some(s) = sender {
            b = b.sender(s).unwrap();
        }
        b.build(&("verify-match", true)).unwrap()
    }

    #[test]
    fn trusted_signal_requires_owner_path_iface_member() {
        let dev = "/net/reactivated/Fprint/Device/0";
        let owner = ":1.7";
        assert!(signal_is_trusted(
            &signal(Some(owner), dev, DEVICE_IFACE, "VerifyStatus"),
            owner,
            dev
        ));
        assert!(!signal_is_trusted(
            &signal(Some(":1.8"), dev, DEVICE_IFACE, "VerifyStatus"),
            owner,
            dev
        ));
        assert!(!signal_is_trusted(
            &signal(None, dev, DEVICE_IFACE, "VerifyStatus"),
            owner,
            dev
        ));
        assert!(!signal_is_trusted(
            &signal(
                Some(owner),
                "/net/reactivated/Fprint/Device/1",
                DEVICE_IFACE,
                "VerifyStatus"
            ),
            owner,
            dev
        ));
        assert!(!signal_is_trusted(
            &signal(Some(owner), dev, "org.example.Evil", "VerifyStatus"),
            owner,
            dev
        ));
        assert!(!signal_is_trusted(
            &signal(Some(owner), dev, DEVICE_IFACE, "EnrollStatus"),
            owner,
            dev
        ));
    }
}

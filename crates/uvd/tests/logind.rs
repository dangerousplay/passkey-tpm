//! `Logind` session policy against a mock systemd-logind on a private bus.

use passkey_tpm_testkit::bus::PrivateBus;
use passkey_tpm_uvd::{Logind, SessionPolicy};
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, Connection};

struct Manager {
    sessions: Vec<(String, u32, String, String, OwnedObjectPath)>,
}

#[interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn list_sessions(&self) -> Vec<(String, u32, String, String, OwnedObjectPath)> {
        self.sessions.clone()
    }
}

struct Session {
    active: bool,
}

#[interface(name = "org.freedesktop.login1.Session")]
impl Session {
    #[zbus(property)]
    fn active(&self) -> bool {
        self.active
    }
}

/// (id, uid, seat, active)
async fn mock_logind(bus: &PrivateBus, sessions: &[(&str, u32, &str, bool)]) -> Connection {
    let conn = bus.connect().await;
    let mut listed = Vec::new();
    for (id, uid, seat, active) in sessions {
        let path = format!("/org/freedesktop/login1/session/_{id}");
        conn.object_server()
            .at(path.as_str(), Session { active: *active })
            .await
            .expect("export session");
        listed.push((
            (*id).to_owned(),
            *uid,
            format!("user{uid}"),
            (*seat).to_owned(),
            OwnedObjectPath::try_from(path).expect("path"),
        ));
    }
    conn.object_server()
        .at("/org/freedesktop/login1", Manager { sessions: listed })
        .await
        .expect("export manager");
    conn.request_name("org.freedesktop.login1")
        .await
        .expect("own login1");
    conn
}

#[tokio::test]
async fn only_an_active_seat_session_counts() {
    let bus = PrivateBus::start();
    let _logind = mock_logind(
        &bus,
        &[
            ("1", 1000, "seat0", false), // alice, switched away
            ("2", 1000, "", true),       // alice over SSH: no seat
            ("3", 1001, "seat0", true),  // bob, in front of the machine
        ],
    )
    .await;
    let policy = Logind::new(bus.connect().await);
    assert!(!policy.is_active(1000).await, "background + seatless only");
    assert!(policy.is_active(1001).await);
    assert!(!policy.is_active(1002).await, "no session at all");
}

#[tokio::test]
async fn fails_closed_without_logind() {
    let bus = PrivateBus::start();
    let policy = Logind::new(bus.connect().await);
    assert!(!policy.is_active(1000).await);
}

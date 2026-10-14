//! `passkey-tpm-tray`: a StatusNotifierItem showing whether passkey-tpm can work in this
//! session, with fingerprint enrollment through fprintd.
//!
//! This library holds the pure parts (status model, finger choice, messages, icon) so they
//! can be unit-tested; [`probe`] talks to D-Bus and the binary wires everything to `ksni`.
//!
//! The tray is informational and runs as the user, like the agent: same-user malware can
//! spoof it. It holds no secrets; fprintd's polkit action authorises enrollment.
#![forbid(unsafe_code)]

pub mod dialog;
pub mod pin;
pub mod probe;

use passkey_tpm_uv::fprintd::{EnrollProgress, EnrollResult};

/// Order in which "Enroll new fingerprint" picks a finger (fprintd finger names).
pub const FINGER_ORDER: [&str; 10] = [
    "right-index-finger",
    "left-index-finger",
    "right-middle-finger",
    "left-middle-finger",
    "right-thumb",
    "left-thumb",
    "right-ring-finger",
    "left-ring-finger",
    "right-little-finger",
    "left-little-finger",
];

/// The first finger in [`FINGER_ORDER`] that isn't in `enrolled`, or `None` if all are.
#[must_use]
pub fn next_finger(enrolled: &[String]) -> Option<&'static str> {
    FINGER_ORDER
        .into_iter()
        .find(|f| !enrolled.iter().any(|e| e == f))
}

/// Human form of an fprintd finger name: `right-index-finger` → `right index finger`.
#[must_use]
pub fn finger_label(name: &str) -> String {
    name.replace('-', " ")
}

/// Fingerprint reader state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reader {
    /// Not probed yet.
    Checking,
    /// fprintd has no usable device, or isn't installed (the reason).
    Missing(String),
    /// A reader exists; the calling user's enrolled fingers (fprintd names).
    Present {
        /// Device name and scan type, e.g. `Goodix MOC (press)`.
        name: String,
        /// Enrolled fingers; `None` if listing them failed.
        enrolled: Option<Vec<String>>,
    },
}

/// Broker (`passkey-tpm-uvd`) state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broker {
    /// Not probed yet.
    Checking,
    /// It answered on the system bus.
    Reachable,
    /// It didn't answer (the reason).
    Unreachable(String),
}

/// Virtual security key (the `passkey-tpm-agent` user unit) state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtualKey {
    /// Not probed yet.
    Checking,
    /// The agent unit is active.
    Active,
    /// The agent unit exists but isn't active (its `ActiveState`).
    Inactive(String),
    /// The agent's state can't be determined (no systemd user manager, or the unit isn't
    /// installed); the reason.
    Unknown(String),
}

/// The calling user's security-key PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinState {
    /// Not probed yet.
    Checking,
    /// A PIN is set.
    Set,
    /// No PIN yet.
    NotSet,
    /// The broker couldn't tell (the reason).
    Unknown(String),
}

/// Everything the tray shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Fingerprint reader.
    pub reader: Reader,
    /// Broker reachability.
    pub broker: Broker,
    /// Virtual key.
    pub key: VirtualKey,
    /// PIN.
    pub pin: PinState,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            reader: Reader::Checking,
            broker: Broker::Checking,
            key: VirtualKey::Checking,
            pin: PinState::Checking,
        }
    }
}

/// What the PIN menu item does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAction {
    /// clientPIN setPIN.
    Set,
    /// clientPIN changePIN.
    Change,
}

/// Overall state, driving the item status, icon colour and tooltip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// The first probe hasn't finished.
    Checking,
    /// Passkeys should work.
    Ready,
    /// The first problem found, as a sentence.
    Problem(String),
}

impl Snapshot {
    /// Whether the user has at least one enrolled fingerprint.
    #[must_use]
    pub fn has_fingerprint(&self) -> bool {
        matches!(&self.reader, Reader::Present { enrolled: Some(f), .. } if !f.is_empty())
    }

    /// The overall state. Problems are reported in order: reader, enrolled fingers, broker,
    /// virtual key. Without a fingerprint a PIN is enough (AD-022), so the reader problems
    /// only count while no PIN is set. An unknown virtual-key state is not a problem
    /// (non-systemd sessions).
    #[must_use]
    pub fn health(&self) -> Health {
        if self.reader == Reader::Checking
            || self.broker == Broker::Checking
            || self.key == VirtualKey::Checking
            || self.pin == PinState::Checking
        {
            return Health::Checking;
        }
        let pin_only = self.pin == PinState::Set;
        let problem = match &self.reader {
            _ if pin_only => None,
            Reader::Missing(_) => Some("No fingerprint reader detected; set a PIN instead"),
            Reader::Present { enrolled: None, .. } => Some("Cannot list enrolled fingerprints"),
            Reader::Present {
                enrolled: Some(fingers),
                ..
            } if fingers.is_empty() => Some("No fingerprint or PIN set up"),
            _ => None,
        }
        .or(match self.broker {
            Broker::Unreachable(_) => Some("passkey-tpm broker unreachable"),
            _ => None,
        })
        .or(match self.key {
            VirtualKey::Inactive(_) => Some("Virtual security key inactive"),
            _ => None,
        });
        problem.map_or(Health::Ready, |p| Health::Problem(p.to_owned()))
    }

    /// Menu line for the reader.
    #[must_use]
    pub fn reader_line(&self) -> String {
        match &self.reader {
            Reader::Checking => "Fingerprint reader: checking…".to_owned(),
            Reader::Missing(_) => "Fingerprint reader: not detected".to_owned(),
            Reader::Present {
                name,
                enrolled: Some(fingers),
            } => match fingers.len() {
                1 => format!("Fingerprint reader: {name}, 1 finger enrolled"),
                n => format!("Fingerprint reader: {name}, {n} fingers enrolled"),
            },
            Reader::Present {
                name,
                enrolled: None,
            } => format!("Fingerprint reader: {name}"),
        }
    }

    /// Menu line for the broker.
    #[must_use]
    pub fn broker_line(&self) -> String {
        match self.broker {
            Broker::Checking => "Broker: checking…",
            Broker::Reachable => "Broker: reachable",
            Broker::Unreachable(_) => "Broker: unreachable",
        }
        .to_owned()
    }

    /// Menu line for the PIN.
    #[must_use]
    pub fn pin_line(&self) -> String {
        match self.pin {
            PinState::Checking => "PIN: checking…",
            PinState::Set if !self.has_fingerprint() => "PIN: set (used instead of a fingerprint)",
            PinState::Set => "PIN: set",
            PinState::NotSet => "PIN: not set",
            PinState::Unknown(_) => "PIN: unknown",
        }
        .to_owned()
    }

    /// The PIN item, once the broker said whether a PIN is set.
    #[must_use]
    pub fn pin_action(&self) -> Option<PinAction> {
        match self.pin {
            PinState::Set => Some(PinAction::Change),
            PinState::NotSet => Some(PinAction::Set),
            PinState::Checking | PinState::Unknown(_) => None,
        }
    }

    /// Menu line for the virtual key.
    #[must_use]
    pub fn key_line(&self) -> String {
        match &self.key {
            VirtualKey::Checking => "Virtual security key: checking…".to_owned(),
            VirtualKey::Active => "Virtual security key: active".to_owned(),
            VirtualKey::Inactive(state) => format!("Virtual security key: inactive ({state})"),
            VirtualKey::Unknown(_) => "Virtual security key: unknown".to_owned(),
        }
    }

    /// The finger "Enroll new fingerprint" would enroll: `None` without a reader (no enroll
    /// item), `Some(None)` when every finger is enrolled.
    #[must_use]
    pub fn enroll_target(&self) -> Option<Option<&'static str>> {
        match &self.reader {
            Reader::Present { enrolled, .. } => {
                Some(next_finger(enrolled.as_deref().unwrap_or_default()))
            }
            _ => None,
        }
    }
}

/// A notification: summary and body.
pub type Message = (String, String);

/// Turns enrollment progress into notifications, counting accepted scans.
#[derive(Debug, Clone)]
pub struct EnrollTracker {
    finger: String,
    stages: Option<u32>,
    passed: u32,
}

impl EnrollTracker {
    /// A tracker for enrolling `finger` (fprintd name).
    #[must_use]
    pub fn new(finger: &str) -> Self {
        Self {
            finger: finger_label(finger),
            stages: None,
            passed: 0,
        }
    }

    /// The notification for a progress event.
    pub fn progress(&mut self, progress: &EnrollProgress) -> Message {
        let summary = format!("Enrolling your {}", self.finger);
        let body = match progress {
            EnrollProgress::Started { stages } => {
                self.stages = *stages;
                match stages {
                    Some(n) => format!("Touch the fingerprint reader ({n} scans needed)."),
                    None => "Touch the fingerprint reader.".to_owned(),
                }
            }
            EnrollProgress::StagePassed => {
                self.passed = self.passed.saturating_add(1);
                match self.stages {
                    Some(n) => format!("Scan {} of {n} accepted. Touch again.", self.passed),
                    None => "Scan accepted. Touch again.".to_owned(),
                }
            }
            EnrollProgress::Retry(status) => retry_hint(status).to_owned(),
        };
        (summary, body)
    }

    /// The notification for the final result.
    #[must_use]
    pub fn result(&self, result: &EnrollResult) -> Message {
        let (summary, body) = match result {
            EnrollResult::Completed => (
                "Fingerprint enrolled".to_owned(),
                format!("Your {} can now confirm passkeys.", self.finger),
            ),
            EnrollResult::Duplicate => (
                "Fingerprint already enrolled".to_owned(),
                "This finger is already enrolled. Try a different finger.".to_owned(),
            ),
            EnrollResult::Failed(status) => (
                "Enrollment failed".to_owned(),
                match status.as_str() {
                    "enroll-data-full" => "The reader has no room for more fingerprints.",
                    "enroll-disconnected" => "The fingerprint reader was disconnected.",
                    _ => "The fingerprint could not be enrolled. Try again.",
                }
                .to_owned(),
            ),
            EnrollResult::NotAuthorized => (
                "Enrollment not authorised".to_owned(),
                "Authentication was refused or cancelled.".to_owned(),
            ),
            EnrollResult::Busy => (
                "Fingerprint reader busy".to_owned(),
                "Another application is using the reader. Try again later.".to_owned(),
            ),
            EnrollResult::Cancelled => (
                "Enrollment cancelled".to_owned(),
                format!("Your {} was not enrolled.", self.finger),
            ),
            EnrollResult::TimedOut => (
                "Enrollment timed out".to_owned(),
                format!("Your {} was not enrolled.", self.finger),
            ),
            EnrollResult::Unavailable(reason) => {
                ("Fingerprint reader unavailable".to_owned(), reason.clone())
            }
        };
        (summary, body)
    }
}

fn retry_hint(status: &str) -> &'static str {
    match status {
        "enroll-swipe-too-short" => "Swipe was too short. Try again.",
        "enroll-finger-not-centered" => "Center your finger on the reader and try again.",
        "enroll-remove-and-retry" => "Lift your finger and try again.",
        _ => "Scan failed. Try again.",
    }
}

/// An ARGB32 (network byte order) pixmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pixmap {
    /// Width and height in pixels.
    pub size: u32,
    /// `size * size * 4` bytes, `A R G B` per pixel, row-major.
    pub data: Vec<u8>,
}

/// Icon colour (RGB) for a health state: blue when ready, amber on problems, grey while
/// checking. Saturated colours stay visible on light and dark panels.
#[must_use]
pub fn health_colour(health: &Health) -> [u8; 3] {
    match health {
        Health::Ready => [0x35, 0x84, 0xe4],
        Health::Problem(_) => [0xe6, 0x61, 0x00],
        Health::Checking => [0x9a, 0x99, 0x96],
    }
}

/// Draws a stylised fingerprint (concentric ridge arcs inside an oval) of `size` pixels.
#[must_use]
pub fn fingerprint_pixmap(size: u32, rgb: [u8; 3]) -> Pixmap {
    const RIDGES: u32 = 5;
    let s = f64::from(size);
    let (cx, cy) = (s * 0.5, s * 0.56);
    // Ridge spacing and stroke width in pixels; the outer ridge nearly fills the icon.
    let spacing = s * 0.42 / f64::from(RIDGES);
    let stroke = (spacing * 0.5).max(1.0);
    let mut data = Vec::with_capacity(usize::try_from(size.saturating_mul(size)).unwrap_or(0) * 4);
    for y in 0..size {
        for x in 0..size {
            let dx = f64::from(x) + 0.5 - cx;
            let dy = (f64::from(y) + 0.5 - cy) * 0.8;
            let d = dx.hypot(dy);
            // Index of the nearest ridge and distance to it.
            let k = (d / spacing).round();
            let off = (d - k * spacing).abs();
            // Open the bottom of the odd ridges and the inner core, like a fingerprint's whorl.
            let angle = dy.atan2(dx).to_degrees();
            let gap = k % 2.0 == 1.0 && (60.0..120.0).contains(&angle);
            let visible = (1.0..=f64::from(RIDGES)).contains(&k) && !gap;
            let coverage = if visible {
                (stroke * 0.5 + 0.5 - off).clamp(0.0, 1.0)
            } else {
                0.0
            };
            // `coverage` is in [0, 1], so the product is in [0, 255].
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let alpha = (coverage * 255.0).round() as u8;
            data.extend_from_slice(&[alpha, rgb[0], rgb[1], rgb[2]]);
        }
    }
    Pixmap { size, data }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    fn ready() -> Snapshot {
        Snapshot {
            reader: Reader::Present {
                name: "Goodix MOC (press)".to_owned(),
                enrolled: Some(owned(&["right-index-finger"])),
            },
            broker: Broker::Reachable,
            key: VirtualKey::Active,
            pin: PinState::NotSet,
        }
    }

    #[test]
    fn next_finger_follows_order_and_skips_enrolled() {
        assert_eq!(next_finger(&[]), Some("right-index-finger"));
        assert_eq!(
            next_finger(&owned(&["right-index-finger"])),
            Some("left-index-finger")
        );
        assert_eq!(
            next_finger(&owned(&["left-index-finger", "unknown-finger"])),
            Some("right-index-finger")
        );
        let all: Vec<String> = FINGER_ORDER.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(next_finger(&all), None);
        assert_eq!(next_finger(&all[..9]), Some("left-little-finger"));
    }

    #[test]
    fn finger_labels() {
        assert_eq!(finger_label("right-index-finger"), "right index finger");
        assert_eq!(finger_label("left-thumb"), "left thumb");
    }

    #[test]
    fn health_is_checking_until_every_probe_ran() {
        assert_eq!(Snapshot::default().health(), Health::Checking);
        let mut s = ready();
        s.key = VirtualKey::Checking;
        assert_eq!(s.health(), Health::Checking);
    }

    #[test]
    fn health_ready_and_unknown_key_is_not_a_problem() {
        assert_eq!(ready().health(), Health::Ready);
        let mut s = ready();
        s.key = VirtualKey::Unknown("no systemd".to_owned());
        assert_eq!(s.health(), Health::Ready);
    }

    #[test]
    fn health_reports_first_problem_in_order() {
        let mut s = ready();
        s.key = VirtualKey::Inactive("failed".to_owned());
        assert_eq!(
            s.health(),
            Health::Problem("Virtual security key inactive".to_owned())
        );
        s.broker = Broker::Unreachable("x".to_owned());
        assert_eq!(
            s.health(),
            Health::Problem("passkey-tpm broker unreachable".to_owned())
        );
        s.reader = Reader::Present {
            name: "r".to_owned(),
            enrolled: Some(Vec::new()),
        };
        assert_eq!(
            s.health(),
            Health::Problem("No fingerprint or PIN set up".to_owned())
        );
        s.reader = Reader::Missing("no device".to_owned());
        assert_eq!(
            s.health(),
            Health::Problem("No fingerprint reader detected; set a PIN instead".to_owned())
        );
    }

    #[test]
    fn pin_replaces_the_fingerprint() {
        let mut s = ready();
        s.reader = Reader::Missing("no device".to_owned());
        s.pin = PinState::Set;
        assert_eq!(s.health(), Health::Ready);
        assert_eq!(s.pin_line(), "PIN: set (used instead of a fingerprint)");
        assert_eq!(s.pin_action(), Some(PinAction::Change));
        s.pin = PinState::NotSet;
        assert_eq!(s.pin_action(), Some(PinAction::Set));
        s.pin = PinState::Checking;
        assert_eq!(s.health(), Health::Checking);
        assert_eq!(s.pin_action(), None);
        assert_eq!(ready().pin_line(), "PIN: not set");
    }

    #[test]
    fn menu_lines() {
        let s = ready();
        assert_eq!(
            s.reader_line(),
            "Fingerprint reader: Goodix MOC (press), 1 finger enrolled"
        );
        assert_eq!(s.broker_line(), "Broker: reachable");
        assert_eq!(s.key_line(), "Virtual security key: active");
        let s = Snapshot {
            reader: Reader::Missing("x".to_owned()),
            broker: Broker::Unreachable("x".to_owned()),
            key: VirtualKey::Inactive("inactive".to_owned()),
            pin: PinState::Unknown("x".to_owned()),
        };
        assert_eq!(s.reader_line(), "Fingerprint reader: not detected");
        assert_eq!(s.broker_line(), "Broker: unreachable");
        assert_eq!(s.key_line(), "Virtual security key: inactive (inactive)");
    }

    #[test]
    fn enroll_target_only_with_reader() {
        assert_eq!(ready().enroll_target(), Some(Some("left-index-finger")));
        let mut s = ready();
        s.reader = Reader::Missing("x".to_owned());
        assert_eq!(s.enroll_target(), None);
        s.reader = Reader::Present {
            name: "r".to_owned(),
            enrolled: Some(FINGER_ORDER.iter().map(|s| (*s).to_owned()).collect()),
        };
        assert_eq!(s.enroll_target(), Some(None));
    }

    #[test]
    fn tracker_counts_scans() {
        let mut t = EnrollTracker::new("right-index-finger");
        let (summary, body) = t.progress(&EnrollProgress::Started { stages: Some(3) });
        assert_eq!(summary, "Enrolling your right index finger");
        assert_eq!(body, "Touch the fingerprint reader (3 scans needed).");
        assert_eq!(
            t.progress(&EnrollProgress::StagePassed).1,
            "Scan 1 of 3 accepted. Touch again."
        );
        assert_eq!(
            t.progress(&EnrollProgress::Retry(
                "enroll-finger-not-centered".to_owned()
            ))
            .1,
            "Center your finger on the reader and try again."
        );
        assert_eq!(
            t.progress(&EnrollProgress::StagePassed).1,
            "Scan 2 of 3 accepted. Touch again."
        );
        assert_eq!(
            t.result(&EnrollResult::Completed),
            (
                "Fingerprint enrolled".to_owned(),
                "Your right index finger can now confirm passkeys.".to_owned()
            )
        );
        assert_eq!(
            t.result(&EnrollResult::NotAuthorized).0,
            "Enrollment not authorised"
        );
    }

    #[test]
    fn pixmap_has_argb_layout_and_ridges() {
        for size in [16, 22, 32, 48] {
            let p = fingerprint_pixmap(size, [1, 2, 3]);
            assert_eq!(p.data.len(), usize::try_from(size * size * 4).unwrap());
            let opaque = p.data.chunks(4).filter(|px| px[0] > 128).count();
            assert!(opaque > usize::try_from(size).unwrap(), "size {size}");
            assert!(p.data.chunks(4).all(|px| px[1..] == [1, 2, 3]));
            // Corners stay transparent.
            assert_eq!(p.data[0], 0);
        }
    }
}

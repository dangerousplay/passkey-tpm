//! In-process fake fprintd for tests (feature `mock`).
//!
//! [`serve`] exports a `net.reactivated.Fprint.Manager` at [`MANAGER_PATH`] and one
//! `net.reactivated.Fprint.Device` at [`DEVICE_PATH`] on the given connection, then requests
//! the name `net.reactivated.Fprint`. After `VerifyStart`, the device emits the scripted
//! `VerifyStatus` results, waiting [`MockFprintd::delay`] before each one. Calls are recorded
//! in [`MockCalls`] for assertions.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, Connection};

pub use crate::fprintd::{MANAGER_PATH, SERVICE};

/// Object path of the single fake device.
pub const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

/// Script for the fake fprintd.
#[derive(Debug, Clone)]
pub struct MockFprintd {
    /// `VerifyStatus` results emitted after `VerifyStart`, in order. `done` is `true` for
    /// final statuses (`verify-match`, `verify-no-match`, `verify-disconnected`,
    /// `verify-unknown-error`). Emission stops after the first final status. An empty list
    /// never emits anything (useful for timeout and cancel tests).
    pub results: Vec<String>,
    /// Delay before each emitted result.
    pub delay: Duration,
    /// Fingers returned by `ListEnrolledFingers`. Empty means the user has no enrolled prints:
    /// `ListEnrolledFingers` and `VerifyStart` fail with `NoEnrolledPrints`.
    pub enrolled: Vec<String>,
}

impl Default for MockFprintd {
    fn default() -> Self {
        Self {
            results: vec!["verify-match".to_owned()],
            delay: Duration::from_millis(10),
            enrolled: vec!["right-index-finger".to_owned()],
        }
    }
}

impl MockFprintd {
    /// A script that emits `results` (each after `delay`) with one enrolled finger.
    #[must_use]
    pub fn with_results(results: &[&str], delay: Duration) -> Self {
        Self {
            results: results.iter().map(|s| (*s).to_owned()).collect(),
            delay,
            ..Self::default()
        }
    }

    /// Sets the user to have no enrolled fingerprints.
    #[must_use]
    pub fn without_enrolled(mut self) -> Self {
        self.enrolled.clear();
        self
    }
}

/// Calls received by the fake device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MockCalls {
    /// Usernames passed to `Claim`, in order.
    pub claims: Vec<String>,
    /// Finger names passed to `VerifyStart`, in order.
    pub verify_starts: Vec<String>,
    /// Number of `VerifyStop` calls.
    pub verify_stops: u32,
    /// Number of `Release` calls.
    pub releases: u32,
    /// Usernames passed to `ListEnrolledFingers`, in order.
    pub list_enrolled: Vec<String>,
}

#[derive(Debug, Default)]
struct DeviceState {
    calls: MockCalls,
    claimed: bool,
    verifying: Option<CancellationToken>,
}

type Shared = Arc<Mutex<DeviceState>>;

fn lock(state: &Shared) -> MutexGuard<'_, DeviceState> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Handle to a served fake fprintd.
#[derive(Debug, Clone)]
pub struct MockHandle {
    state: Shared,
}

impl MockHandle {
    /// Snapshot of the calls received so far.
    #[must_use]
    pub fn calls(&self) -> MockCalls {
        lock(&self.state).calls.clone()
    }

    /// Whether the device is currently claimed.
    #[must_use]
    pub fn is_claimed(&self) -> bool {
        lock(&self.state).claimed
    }

    /// Whether a verification is currently running.
    #[must_use]
    pub fn is_verifying(&self) -> bool {
        lock(&self.state).verifying.is_some()
    }
}

/// fprintd-style D-Bus errors (`net.reactivated.Fprint.Error.*`).
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
enum FprintError {
    #[zbus(error)]
    ZBus(zbus::Error),
    ClaimDevice(String),
    AlreadyInUse(String),
    NoEnrolledPrints(String),
    NoActionInProgress(String),
}

struct Manager;

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    #[zbus(name = "GetDevices")]
    fn get_devices(&self) -> Vec<OwnedObjectPath> {
        OwnedObjectPath::try_from(DEVICE_PATH)
            .map(|p| vec![p])
            .unwrap_or_default()
    }

    #[zbus(name = "GetDefaultDevice")]
    fn get_default_device(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        OwnedObjectPath::try_from(DEVICE_PATH).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }
}

struct Device {
    script: MockFprintd,
    state: Shared,
}

fn is_final(result: &str) -> bool {
    matches!(
        result,
        "verify-match" | "verify-no-match" | "verify-disconnected" | "verify-unknown-error"
    )
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    #[zbus(name = "Claim")]
    fn claim(&self, username: String) -> Result<(), FprintError> {
        let mut st = lock(&self.state);
        st.calls.claims.push(username);
        if st.claimed {
            return Err(FprintError::AlreadyInUse(
                "device already claimed".to_owned(),
            ));
        }
        st.claimed = true;
        Ok(())
    }

    #[zbus(name = "Release")]
    fn release(&self) -> Result<(), FprintError> {
        let mut st = lock(&self.state);
        st.calls.releases = st.calls.releases.saturating_add(1);
        if !st.claimed {
            return Err(FprintError::ClaimDevice("device not claimed".to_owned()));
        }
        st.claimed = false;
        if let Some(token) = st.verifying.take() {
            token.cancel();
        }
        Ok(())
    }

    #[zbus(name = "ListEnrolledFingers")]
    fn list_enrolled_fingers(&self, username: String) -> Result<Vec<String>, FprintError> {
        lock(&self.state).calls.list_enrolled.push(username);
        if self.script.enrolled.is_empty() {
            return Err(FprintError::NoEnrolledPrints(
                "no enrolled prints".to_owned(),
            ));
        }
        Ok(self.script.enrolled.clone())
    }

    #[zbus(name = "VerifyStart")]
    fn verify_start(
        &self,
        finger_name: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(), FprintError> {
        let token = {
            let mut st = lock(&self.state);
            st.calls.verify_starts.push(finger_name);
            if !st.claimed {
                return Err(FprintError::ClaimDevice("device not claimed".to_owned()));
            }
            if st.verifying.is_some() {
                return Err(FprintError::AlreadyInUse("verify in progress".to_owned()));
            }
            if self.script.enrolled.is_empty() {
                return Err(FprintError::NoEnrolledPrints(
                    "no enrolled prints".to_owned(),
                ));
            }
            let token = CancellationToken::new();
            st.verifying = Some(token.clone());
            token
        };
        let emitter = emitter.into_owned();
        let results = self.script.results.clone();
        let delay = self.script.delay;
        tokio::spawn(async move {
            for result in results {
                tokio::select! {
                    () = token.cancelled() => return,
                    () = tokio::time::sleep(delay) => {}
                }
                let done = is_final(&result);
                if Self::verify_status(&emitter, &result, done).await.is_err() || done {
                    return;
                }
            }
        });
        Ok(())
    }

    #[zbus(name = "VerifyStop")]
    fn verify_stop(&self) -> Result<(), FprintError> {
        let mut st = lock(&self.state);
        st.calls.verify_stops = st.calls.verify_stops.saturating_add(1);
        match st.verifying.take() {
            Some(token) => {
                token.cancel();
                Ok(())
            }
            None => Err(FprintError::NoActionInProgress(
                "no verification in progress".to_owned(),
            )),
        }
    }

    /// `VerifyStatus(s result, b done)`.
    #[zbus(signal, name = "VerifyStatus")]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;
}

/// Serves `mock` on `conn` and requests the name `net.reactivated.Fprint`.
///
/// # Errors
///
/// Returns an error if the objects can't be registered or the name can't be acquired.
pub async fn serve(conn: &Connection, mock: MockFprintd) -> zbus::Result<MockHandle> {
    let state: Shared = Arc::default();
    let server = conn.object_server();
    server.at(MANAGER_PATH, Manager).await?;
    server
        .at(
            DEVICE_PATH,
            Device {
                script: mock,
                state: Arc::clone(&state),
            },
        )
        .await?;
    conn.request_name(SERVICE).await?;
    Ok(MockHandle { state })
}

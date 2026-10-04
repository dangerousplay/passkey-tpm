//! passkey-tpm broker (ADR 0003): the only process that uses passkey keys in the TPM.
//!
//! Callers reach it over the system bus. The calling user is taken from the bus
//! (`GetConnectionUnixUser`), never from request data, and every operation is confined to
//! that user's credentials. Fingerprint verification runs here, against fprintd, for that
//! user only; a [`UvEvidence`] is created only from fprintd's `verify-match`.

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use passkey_tpm_core::ctap2::{Authenticator, Pending, Step, UserInfo, UvOutcome};
use passkey_tpm_core::ctaphid::MAX_MSG;
use passkey_tpm_core::evidence::UvEvidence;
use passkey_tpm_core::tpm_iface::{TpmOps, Uid};
use passkey_tpm_uv::fprintd::{self, UvResult};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use zbus::message::Header;
use zbus::{fdo, interface, Connection};

pub const BUS_NAME: &str = "io.github.dangerousplay.PasskeyTpm1";
pub const OBJECT_PATH: &str = "/io/github/dangerousplay/PasskeyTpm1";
/// CTAP status byte returned when the request is larger than maxMsgSize.
const STATUS_INVALID_LENGTH: u8 = 0x03;
const STATUS_OTHER: u8 = 0x7F;

enum Job {
    Prepare {
        uid: Uid,
        info: UserInfo,
        request: Vec<u8>,
        reply: oneshot::Sender<Step>,
    },
    Complete {
        pending: Box<Pending>,
        outcome: UvOutcome,
        reply: oneshot::Sender<Vec<u8>>,
    },
}

/// Milliseconds since the worker started (monotonic; the authenticator's clock).
fn now_ms(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Handle to the thread that owns the TPM backend. TPM contexts aren't `Send`, and all TPM
/// commands must be serialised anyway, so one thread does all TPM work.
#[derive(Clone, Debug)]
pub struct TpmWorker {
    tx: mpsc::Sender<Job>,
}

impl TpmWorker {
    /// Spawns the worker; `make` builds the backend on the worker thread.
    ///
    /// # Errors
    /// If the thread can't be spawned.
    pub fn spawn<T, F>(make: F) -> std::io::Result<Self>
    where
        T: TpmOps,
        F: FnOnce() -> T + Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("passkey-tpm-tpm".into())
            .spawn(move || {
                let mut auth = Authenticator::new(make());
                let start = std::time::Instant::now();
                for job in rx {
                    match job {
                        Job::Prepare {
                            uid,
                            info,
                            request,
                            reply,
                        } => {
                            let _ = reply.send(auth.prepare(uid, info, &request, now_ms(start)));
                        }
                        Job::Complete {
                            pending,
                            outcome,
                            reply,
                        } => {
                            let _ = reply.send(auth.complete(pending, outcome, now_ms(start)));
                        }
                    }
                }
            })?;
        Ok(Self { tx })
    }

    async fn prepare(&self, uid: Uid, info: UserInfo, request: Vec<u8>) -> Option<Step> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Job::Prepare {
                uid,
                info,
                request,
                reply,
            })
            .ok()?;
        rx.await.ok()
    }

    async fn complete(&self, pending: Box<Pending>, outcome: UvOutcome) -> Option<Vec<u8>> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Job::Complete {
                pending,
                outcome,
                reply,
            })
            .ok()?;
        rx.await.ok()
    }
}

/// Resolves a uid to a login name (NSS, so authd/SSSD users work too).
pub trait UserLookup: Send + Sync {
    fn username(&self, uid: u32) -> Option<String>;
}

/// [`UserLookup`] through the system's NSS.
#[derive(Debug, Default, Clone, Copy)]
pub struct NssUsers;

impl UserLookup for NssUsers {
    fn username(&self, uid: u32) -> Option<String> {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.name)
    }
}

/// The D-Bus service object.
pub struct Broker {
    worker: TpmWorker,
    fprintd: Connection,
    users: Box<dyn UserLookup>,
    verify_timeout: Duration,
    cancels: Arc<Mutex<HashMap<u32, (u64, CancellationToken)>>>,
    next_request: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("verify_timeout", &self.verify_timeout)
            .finish_non_exhaustive()
    }
}

impl Broker {
    /// `fprintd` is the (system) bus connection used to reach fprintd.
    #[must_use]
    pub fn new(
        worker: TpmWorker,
        fprintd: Connection,
        users: Box<dyn UserLookup>,
        verify_timeout: Duration,
    ) -> Self {
        Self {
            worker,
            fprintd,
            users,
            verify_timeout,
            cancels: Arc::default(),
            next_request: std::sync::atomic::AtomicU64::new(0),
        }
    }

    async fn caller_uid(conn: &Connection, header: &Header<'_>) -> fdo::Result<u32> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
        let dbus = fdo::DBusProxy::new(conn).await?;
        dbus.get_connection_unix_user(sender.clone().into()).await
    }

    /// Registers a cancel token for `uid`'s new request; a still-pending older request of the
    /// same user is cancelled (only one fingerprint prompt per user at a time).
    fn register_cancel(&self, uid: u32) -> (u64, CancellationToken) {
        let seq = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let token = CancellationToken::new();
        if let Ok(mut map) = self.cancels.lock() {
            if let Some((_, old)) = map.insert(uid, (seq, token.clone())) {
                old.cancel();
            }
        }
        (seq, token)
    }

    /// Removes `uid`'s token if it still belongs to request `seq`.
    fn clear_cancel(&self, uid: u32, seq: u64) {
        if let Ok(mut map) = self.cancels.lock() {
            if map.get(&uid).is_some_and(|(s, _)| *s == seq) {
                map.remove(&uid);
            }
        }
    }

    async fn run(&self, uid: u32, request: Vec<u8>) -> Vec<u8> {
        if request.len() > MAX_MSG {
            return vec![STATUS_INVALID_LENGTH];
        }
        // Audit trail in the journal: which user asked for which CTAP command.
        #[allow(clippy::print_stderr)]
        {
            eprintln!(
                "request uid={uid} command={:#04x} len={}",
                request.first().copied().unwrap_or(0),
                request.len()
            );
        }
        let username = self.users.username(uid);
        let uv_enrolled = match &username {
            Some(name) => fprintd::has_enrolled(&self.fprintd, name)
                .await
                .unwrap_or(false),
            None => false,
        };
        let info = UserInfo { uv_enrolled };
        let Some(step) = self.worker.prepare(Uid(uid), info, request).await else {
            return vec![STATUS_OTHER];
        };
        let pending = match step {
            Step::Done(response) => return response,
            Step::NeedUv(pending) => pending,
        };
        let outcome = match username {
            None => UvOutcome::Unavailable,
            Some(name) => {
                let (seq, token) = self.register_cancel(uid);
                let result =
                    fprintd::verify(&self.fprintd, &name, self.verify_timeout, token).await;
                self.clear_cancel(uid, seq);
                match result {
                    // The only place evidence is created: a real fprintd match for this uid.
                    UvResult::Match => UvOutcome::Matched(UvEvidence::from_fprintd_match(uid)),
                    UvResult::NoMatch => UvOutcome::NoMatch,
                    UvResult::Cancelled => UvOutcome::Cancelled,
                    UvResult::TimedOut => UvOutcome::TimedOut,
                    UvResult::Unavailable(_) => UvOutcome::Unavailable,
                }
            }
        };
        self.worker
            .complete(pending, outcome)
            .await
            .unwrap_or_else(|| vec![STATUS_OTHER])
    }
}

#[interface(name = "io.github.dangerousplay.PasskeyTpm1")]
impl Broker {
    /// Processes one CTAP2 request (command byte + CBOR) for the calling user and returns
    /// the response (status byte + CBOR). May wait up to the verify timeout for a fingerprint.
    async fn ctap(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        request: Vec<u8>,
    ) -> fdo::Result<Vec<u8>> {
        let uid = Self::caller_uid(conn, &header).await?;
        Ok(self.run(uid, request).await)
    }

    /// Cancels the calling user's pending fingerprint request, if any.
    async fn cancel(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let uid = Self::caller_uid(conn, &header).await?;
        if let Ok(map) = self.cancels.lock() {
            if let Some((_, token)) = map.get(&uid) {
                token.cancel();
            }
        }
        Ok(())
    }
}

/// Exports `broker` on `conn` and claims [`BUS_NAME`].
///
/// # Errors
/// D-Bus errors (e.g. the name is already owned or the policy forbids owning it).
pub async fn serve(conn: &Connection, broker: Broker) -> zbus::Result<()> {
    conn.object_server().at(OBJECT_PATH, broker).await?;
    conn.request_name(BUS_NAME).await?;
    Ok(())
}

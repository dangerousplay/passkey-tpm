//! [`TpmOps`] implementation used by the broker: one TPM context, per-user gate state
//! provisioned on the first makeCredential or setPIN and persisted under the broker's state directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use passkey_tpm_core::tpm_iface::{
    CredBlobs, CredProtect, GateKind, ResidentEntry, RpIdHash, TpmError, TpmOps, Uid,
};
use passkey_tpm_wire::credid::{split_id, TAG_LEN};
use passkey_tpm_wire::gatestore::GateStore;
use tss_esapi::constants::CapabilityType;
use tss_esapi::structures::CapabilityData;
use tss_esapi::Context;

use crate::error::{Error, Result};
use crate::gates::GateIndexes;
use crate::policy::GateNames;
use crate::sign::UserGates;
use crate::srk::Srk;
use crate::{credential, credtag, fsutil, gates, nvgate, pin, sign, srk};

const GATES_FILE: &str = "gates.v1";
const PIN_RETRIES_FILE: &str = "pin_retries";
const RESIDENT_FILE: &str = "resident.v1";
/// Revoked credential-ID tags, 16 bytes each.
const REVOKED_FILE: &str = "revoked.v1";
/// CTAP 2.1 maximum PIN retries.
const MAX_PIN_RETRIES: u8 = 8;
/// Per-uid wrong-PIN ledgers (HARD-05), outside the user directories so that
/// authenticatorReset doesn't clear them.
const DA_DIR: &str = "da";

/// Wrong PINs a uid has charged to the TPM-wide dictionary-attack counter and not yet had
/// forgiven. File format: `u32 failures ‖ u64 since` (big-endian, Unix seconds).
#[derive(Debug, Clone, Copy)]
struct DaLedger {
    failures: u32,
    /// Start of the current recovery interval.
    since: u64,
}

impl DaLedger {
    /// The ledger at `now` after the TPM forgave one failure per `interval_s` seconds. An
    /// interval of 0 forgives nothing, so the ledger doesn't decay either.
    fn decayed(self, now: u64, interval_s: u32) -> Self {
        let mut ledger = self;
        if interval_s > 0 {
            let interval = u64::from(interval_s);
            let forgiven = now.saturating_sub(ledger.since) / interval;
            ledger.failures = ledger
                .failures
                .saturating_sub(u32::try_from(forgiven).unwrap_or(u32::MAX));
            ledger.since = ledger
                .since
                .saturating_add(forgiven.saturating_mul(interval));
        }
        if ledger.failures == 0 {
            ledger.since = now;
        }
        ledger
    }

    fn encode(self) -> [u8; 12] {
        let mut out = [0; 12];
        out[..4].copy_from_slice(&self.failures.to_be_bytes());
        out[4..].copy_from_slice(&self.since.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let (failures, since) = bytes.split_first_chunk::<4>()?;
        Some(Self {
            failures: u32::from_be_bytes(*failures),
            since: u64::from_be_bytes(since.try_into().ok()?),
        })
    }
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct User {
    store: GateStore,
    names: GateNames,
}

/// The broker's TPM backend.
pub struct TpmBackend {
    ctx: Context,
    state_dir: PathBuf,
    srk: Option<Srk>,
    users: HashMap<u32, User>,
}

impl std::fmt::Debug for TpmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmBackend")
            .field("state_dir", &self.state_dir)
            .field("users_loaded", &self.users.len())
            .finish_non_exhaustive()
    }
}

impl TpmBackend {
    /// `state_dir` must be private to the broker (systemd `StateDirectory`, mode 0700).
    #[must_use]
    pub fn new(ctx: Context, state_dir: PathBuf) -> Self {
        Self {
            ctx,
            state_dir,
            srk: None,
            users: HashMap::new(),
        }
    }

    fn srk(&mut self) -> Result<Srk> {
        if let Some(srk) = &self.srk {
            return Ok(srk.clone());
        }
        let srk = srk::ensure(&mut self.ctx)?;
        self.srk = Some(srk.clone());
        Ok(srk)
    }

    fn user_dir(&self, uid: Uid) -> PathBuf {
        self.state_dir.join(uid.0.to_string())
    }

    /// Three NV indexes in our range not currently defined on the TPM.
    fn allocate_nv_indexes(&mut self) -> Result<GateIndexes> {
        let (data, _) = self.ctx.execute_without_session(|ctx| {
            ctx.get_capability(CapabilityType::Handles, nvgate::NV_BASE, 1024)
        })?;
        let CapabilityData::Handles(list) = data else {
            return Err(Error::Corrupt("handle list"));
        };
        let used: Vec<u32> = list.iter().map(|h| u32::from(*h)).collect();
        let mut free = (nvgate::NV_BASE..=nvgate::NV_LAST).filter(|i| !used.contains(i));
        let mut next = || free.next().ok_or(Error::Corrupt("no free NV index"));
        Ok(GateIndexes {
            pin: next()?,
            uv: next()?,
            up: next()?,
        })
    }

    /// Loads `uid`'s persisted gate state; `false` if the user has none yet.
    fn load(&mut self, uid: Uid) -> Result<bool> {
        if self.users.contains_key(&uid.0) {
            return Ok(true);
        }
        let mut store = match std::fs::read(self.user_dir(uid).join(GATES_FILE)) {
            Ok(bytes) => GateStore::decode(&bytes).map_err(|_| Error::Corrupt("gates.v1"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if store.pending_pin.is_some() {
            // A PIN change was interrupted (HARD-06): finish it, so the new PIN is in force.
            let srk = self.srk()?;
            if store.srk_name != srk.name {
                return Err(Error::SrkMismatch);
            }
            store = pin::complete(&mut self.ctx, &srk, &store)?;
            self.write_gates(uid, &store)?;
        }
        self.insert_user(uid, store)?;
        Ok(true)
    }

    /// Persists `uid`'s gate state.
    fn write_gates(&self, uid: Uid, store: &GateStore) -> Result<()> {
        let bytes = store.encode().map_err(|_| Error::Corrupt("gates.v1"))?;
        let dir = self.user_dir(uid);
        create_private_dir(&dir)?;
        Ok(fsutil::write_atomic(&dir.join(GATES_FILE), &bytes)?)
    }

    fn insert_user(&mut self, uid: Uid, store: GateStore) -> Result<()> {
        let srk = self.srk()?;
        if store.srk_name != srk.name {
            return Err(Error::SrkMismatch);
        }
        let names = gates::names(&mut self.ctx, &store)?;
        self.users.insert(uid.0, User { store, names });
        Ok(())
    }

    /// Provisioning happens only for operations that create state (makeCredential, setPIN),
    /// never for read-only ones (HARD-09). Gates that can't be persisted are undefined again.
    fn load_or_provision(&mut self, uid: Uid) -> Result<()> {
        if self.load(uid)? {
            return Ok(());
        }
        let srk = self.srk()?;
        let indexes = self.allocate_nv_indexes()?;
        let store = gates::provision(&mut self.ctx, &srk, indexes)?;
        if let Err(e) = self.write_gates(uid, &store) {
            gates::discard(&mut self.ctx, &store);
            return Err(e);
        }
        self.insert_user(uid, store)
    }

    /// Like [`Self::with_user`] for operations that only read: a user without state gets
    /// `absent` and nothing is provisioned.
    fn with_existing_user<T>(
        &mut self,
        uid: Uid,
        absent: std::result::Result<T, TpmError>,
        f: impl FnOnce(&mut Context, &Srk, &User) -> Result<T>,
    ) -> std::result::Result<T, TpmError> {
        match self.load(uid) {
            Ok(true) => self.with_user(uid, f),
            Ok(false) => absent,
            Err(e) => Err(e.to_tpm_error()),
        }
    }

    /// Runs `f` with `uid`'s gate state, provisioning it first if needed.
    fn with_user<T>(
        &mut self,
        uid: Uid,
        f: impl FnOnce(&mut Context, &Srk, &User) -> Result<T>,
    ) -> std::result::Result<T, TpmError> {
        let run = || -> Result<T> {
            self.load_or_provision(uid)?;
            let srk = self.srk()?;
            let user = self.users.get(&uid.0).ok_or(Error::Corrupt("user state"))?;
            f(&mut self.ctx, &srk, user)
        };
        run().map_err(|e| e.to_tpm_error())
    }
}

impl TpmBackend {
    /// Computes `uid`'s next gate state with `f`, persists it, then caches it. On any error
    /// the cached state is dropped, so the next request reloads (and repairs) it from disk.
    fn replace_gates(
        &mut self,
        uid: Uid,
        f: impl FnOnce(&mut Context, &Srk, &User) -> Result<GateStore>,
    ) -> std::result::Result<(), TpmError> {
        let result = self.with_user(uid, f).and_then(|store| {
            self.write_gates(uid, &store)
                .map_err(|e| e.to_tpm_error())?;
            Ok(store)
        });
        match result {
            Ok(store) => {
                if let Some(user) = self.users.get_mut(&uid.0) {
                    user.store = store;
                }
                Ok(())
            }
            Err(e) => {
                self.users.remove(&uid.0);
                Err(e)
            }
        }
    }

    fn revoked_tags(&self, uid: Uid) -> std::result::Result<Vec<[u8; TAG_LEN]>, TpmError> {
        match std::fs::read(self.user_dir(uid).join(REVOKED_FILE)) {
            Ok(bytes) if bytes.len() % TAG_LEN == 0 => Ok(bytes.as_chunks::<TAG_LEN>().0.to_vec()),
            // A corrupt list fails closed for every credential of this user.
            Ok(_) => Err(TpmError::Unavailable),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(TpmError::Unavailable),
        }
    }

    fn is_revoked(&self, uid: Uid, id: &[u8]) -> std::result::Result<bool, TpmError> {
        let Ok((_, tag)) = split_id(id) else {
            return Ok(false);
        };
        Ok(self.revoked_tags(uid)?.contains(&tag))
    }
}

impl TpmBackend {
    fn da_ledger_path(&self, uid: Uid) -> PathBuf {
        self.state_dir.join(DA_DIR).join(uid.0.to_string())
    }

    fn read_da_ledger(&self, uid: Uid) -> std::result::Result<DaLedger, TpmError> {
        match std::fs::read(self.da_ledger_path(uid)) {
            // A corrupt ledger fails closed: the budget counts as spent.
            Ok(bytes) => DaLedger::decode(&bytes).ok_or(TpmError::Lockout),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DaLedger {
                failures: 0,
                since: 0,
            }),
            Err(_) => Err(TpmError::Unavailable),
        }
    }

    fn write_da_ledger(&self, uid: Uid, ledger: DaLedger) -> std::result::Result<(), TpmError> {
        create_private_dir(&self.state_dir.join(DA_DIR)).map_err(|_| TpmError::Unavailable)?;
        fsutil::write_atomic(&self.da_ledger_path(uid), &ledger.encode())
            .map_err(|_| TpmError::Unavailable)
    }

    /// Runs `check`, a dictionary-attack-counted PIN check, against `uid`'s wrong-PIN budget
    /// (HARD-05). The budget is one CTAP retry cycle (8), and below the TPM's `maxTries`, so
    /// one uid can't lock out the TPM for everyone. It survives authenticatorReset and is
    /// forgiven at the TPM's own rate, one failure per recovery interval. The failure is
    /// charged before the check (crash-safe, like the CTAP retry counter) and refunded unless
    /// the TPM reports a wrong PIN.
    fn da_charged<T>(
        &mut self,
        uid: Uid,
        check: impl FnOnce(&mut Self) -> std::result::Result<T, TpmError>,
    ) -> std::result::Result<T, TpmError> {
        let da = crate::health::da_status(&mut self.ctx).map_err(|e| e.to_tpm_error())?;
        let budget = u32::from(MAX_PIN_RETRIES).min(da.max_tries.saturating_sub(1));
        let ledger = self
            .read_da_ledger(uid)?
            .decayed(now_s(), da.recovery_interval_s);
        if ledger.failures >= budget {
            return Err(TpmError::Lockout);
        }
        self.write_da_ledger(
            uid,
            DaLedger {
                failures: ledger.failures.saturating_add(1),
                since: ledger.since,
            },
        )?;
        let result = check(self);
        if !matches!(result, Err(TpmError::WrongPin)) {
            // Best effort: a failed refund only over-counts, the safe direction.
            let _ = self.write_da_ledger(uid, ledger);
        }
        result
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    Ok(())
}

impl TpmOps for TpmBackend {
    fn create_credential(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        protect: CredProtect,
        with_hmac: bool,
    ) -> std::result::Result<CredBlobs, TpmError> {
        self.with_user(uid, |ctx, srk, user| {
            credential::create(ctx, srk, &user.names, rp, protect, with_hmac)
        })
    }

    fn credential_id(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        blobs: &CredBlobs,
    ) -> std::result::Result<Vec<u8>, TpmError> {
        self.with_existing_user(uid, Err(TpmError::Unavailable), |_, _, user| {
            credtag::seal(&user.store.cred_mac_key.0, rp, blobs)
        })
    }

    fn open_credential_id(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        id: &[u8],
    ) -> std::result::Result<Option<CredBlobs>, TpmError> {
        if self.is_revoked(uid, id)? {
            return Ok(None);
        }
        self.with_existing_user(uid, Ok(None), |_, _, user| {
            Ok(credtag::open(&user.store.cred_mac_key.0, rp, id))
        })
    }

    fn public_key(
        &mut self,
        blobs: &CredBlobs,
    ) -> std::result::Result<([u8; 32], [u8; 32]), TpmError> {
        credential::public_point(blobs).map_err(|e| e.to_tpm_error())
    }

    fn sign(
        &mut self,
        uid: Uid,
        blobs: &CredBlobs,
        rp: &RpIdHash,
        gate: GateKind,
        digest: &[u8; 32],
    ) -> std::result::Result<Vec<u8>, TpmError> {
        // No gates: the credential can't be this user's.
        self.with_existing_user(uid, Err(TpmError::PolicyFailed), |ctx, srk, user| {
            let gates = UserGates {
                store: &user.store,
                names: &user.names,
            };
            sign::sign(ctx, srk, &gates, blobs, rp, gate, digest)
        })
    }

    fn hmac(
        &mut self,
        uid: Uid,
        blobs: &CredBlobs,
        rp: &RpIdHash,
        gate: GateKind,
        salt: &[u8; 32],
    ) -> std::result::Result<[u8; 32], TpmError> {
        self.with_existing_user(uid, Err(TpmError::PolicyFailed), |ctx, srk, user| {
            let gates = UserGates {
                store: &user.store,
                names: &user.names,
            };
            sign::hmac(ctx, srk, &gates, blobs, rp, gate, salt)
        })
    }

    fn change_pin(
        &mut self,
        uid: Uid,
        old: Option<&[u8; 16]>,
        new: &[u8; 16],
    ) -> std::result::Result<(), TpmError> {
        let pending = match old {
            None => self.with_user(uid, |ctx, srk, user| {
                pin::begin_set(ctx, srk, &user.store, new)
            })?,
            // The TPM checks the old PIN against the DA-protected gate.
            Some(old) => self.da_charged(uid, |this| {
                this.with_user(uid, |ctx, srk, user| {
                    pin::begin_change(ctx, srk, &user.store, old, new)
                })
            })?,
        };
        // Persist the new PIN before the NV index is redefined, then complete and clear the
        // pending change (HARD-06). A crash or error in between is completed on the next load,
        // so the PIN is the old or the new one, never neither.
        self.replace_gates(uid, |_, _, _| Ok(pending))?;
        self.replace_gates(uid, |ctx, srk, user| pin::complete(ctx, srk, &user.store))
    }

    fn verify_pin(&mut self, uid: Uid, pin_hash: &[u8; 16]) -> std::result::Result<(), TpmError> {
        if !self.load(uid).map_err(|e| e.to_tpm_error())? {
            // Same outcome as a provisioned user without a PIN (`pin::verify`).
            return Err(TpmError::PolicyFailed);
        }
        self.da_charged(uid, |this| {
            this.with_user(uid, |ctx, srk, user| {
                pin::verify(ctx, srk, &user.store, pin_hash)
            })
        })
    }

    fn pin_is_set(&mut self, uid: Uid) -> std::result::Result<bool, TpmError> {
        self.with_existing_user(uid, Ok(false), |_, _, user| {
            Ok(user.store.pin_bootstrap.is_none())
        })
    }

    fn pin_retries(&mut self, uid: Uid) -> std::result::Result<u8, TpmError> {
        match std::fs::read(self.user_dir(uid).join(PIN_RETRIES_FILE)) {
            Ok(bytes) => match bytes.as_slice() {
                [n] if *n <= MAX_PIN_RETRIES => Ok(*n),
                // A corrupt counter fails closed: treat it as blocked.
                _ => Ok(0),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MAX_PIN_RETRIES),
            Err(_) => Err(TpmError::Unavailable),
        }
    }

    fn set_pin_retries(&mut self, uid: Uid, retries: u8) -> std::result::Result<(), TpmError> {
        let dir = self.user_dir(uid);
        create_private_dir(&dir).map_err(|_| TpmError::Unavailable)?;
        fsutil::write_atomic(&dir.join(PIN_RETRIES_FILE), &[retries.min(MAX_PIN_RETRIES)])
            .map_err(|_| TpmError::Unavailable)
    }

    fn resident_entries(&mut self, uid: Uid) -> std::result::Result<Vec<ResidentEntry>, TpmError> {
        match std::fs::read(self.user_dir(uid).join(RESIDENT_FILE)) {
            Ok(bytes) => {
                passkey_tpm_wire::resident::decode(&bytes).map_err(|_| TpmError::Unavailable)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(TpmError::Unavailable),
        }
    }

    fn store_resident_entries(
        &mut self,
        uid: Uid,
        entries: &[ResidentEntry],
    ) -> std::result::Result<(), TpmError> {
        let dir = self.user_dir(uid);
        create_private_dir(&dir).map_err(|_| TpmError::Unavailable)?;
        let bytes =
            passkey_tpm_wire::resident::encode(entries).map_err(|_| TpmError::Unavailable)?;
        fsutil::write_atomic(&dir.join(RESIDENT_FILE), &bytes).map_err(|_| TpmError::Unavailable)
    }

    fn revoke_credential(&mut self, uid: Uid, id: &[u8]) -> std::result::Result<(), TpmError> {
        let (_, tag) = split_id(id).map_err(|_| TpmError::PolicyFailed)?;
        let mut tags = self.revoked_tags(uid)?;
        if !tags.contains(&tag) {
            tags.push(tag);
        }
        let dir = self.user_dir(uid);
        create_private_dir(&dir).map_err(|_| TpmError::Unavailable)?;
        fsutil::write_atomic(&dir.join(REVOKED_FILE), &tags.concat())
            .map_err(|_| TpmError::Unavailable)
    }

    fn reset_user(&mut self, uid: Uid) -> std::result::Result<(), TpmError> {
        let dir = self.user_dir(uid);
        let result =
            self.with_existing_user(uid, Ok(()), |ctx, _, user| gates::remove(ctx, &user.store));
        self.users.remove(&uid.0);
        result?;
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(TpmError::Unavailable),
        }
    }

    fn health(&mut self) -> std::result::Result<(), TpmError> {
        let pinned = self.users.values().next().map(|u| u.store.srk_name.clone());
        match pinned {
            Some(name) => crate::health::check(&mut self.ctx, &name).map_err(|e| e.to_tpm_error()),
            None => self.srk().map(|_| ()).map_err(|e| e.to_tpm_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DaLedger;

    fn ledger(failures: u32, since: u64) -> DaLedger {
        DaLedger { failures, since }
    }

    #[test]
    fn da_ledger_forgives_one_failure_per_recovery_interval() {
        let l = ledger(5, 1000).decayed(1000 + 2 * 60 + 59, 60);
        assert_eq!(
            (l.failures, l.since),
            (3, 1120),
            "partial interval carries over"
        );
        let l = ledger(2, 1000).decayed(1_000_000, 60);
        assert_eq!((l.failures, l.since), (0, 1_000_000), "restarts when empty");
        let l = ledger(5, 1000).decayed(u64::MAX, 0);
        assert_eq!(l.failures, 5, "interval 0 forgives nothing");
        let l = ledger(5, 1000).decayed(10, 60);
        assert_eq!((l.failures, l.since), (5, 1000), "clock went backwards");
    }

    #[test]
    fn da_ledger_round_trips_and_rejects_bad_lengths() {
        let l = DaLedger::decode(&ledger(7, 0x0102_0304_0506).encode()).unwrap();
        assert_eq!((l.failures, l.since), (7, 0x0102_0304_0506));
        assert!(DaLedger::decode(&[0; 11]).is_none());
        assert!(DaLedger::decode(&[0; 13]).is_none());
        assert!(DaLedger::decode(&[]).is_none());
    }
}

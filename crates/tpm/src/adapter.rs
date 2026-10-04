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
        let store = match std::fs::read(self.user_dir(uid).join(GATES_FILE)) {
            Ok(bytes) => GateStore::decode(&bytes).map_err(|_| Error::Corrupt("gates.v1"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        self.insert_user(uid, store)?;
        Ok(true)
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
        let dir = self.user_dir(uid);
        let persisted = store
            .encode()
            .map_err(|_| Error::Corrupt("gates.v1"))
            .and_then(|bytes| {
                create_private_dir(&dir)?;
                Ok(fsutil::write_atomic(&dir.join(GATES_FILE), &bytes)?)
            });
        if let Err(e) = persisted {
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
        let dir = self.user_dir(uid);
        let updated = self.with_user(uid, |ctx, srk, user| match old {
            None => pin::set_pin(ctx, srk, &user.store, new),
            Some(old) => pin::change_pin(ctx, srk, &user.store, old, new),
        })?;
        let bytes = updated.encode().map_err(|_| TpmError::Unavailable)?;
        fsutil::write_atomic(&dir.join(GATES_FILE), &bytes).map_err(|_| TpmError::Unavailable)?;
        if let Some(user) = self.users.get_mut(&uid.0) {
            user.store = updated;
        }
        Ok(())
    }

    fn verify_pin(&mut self, uid: Uid, pin_hash: &[u8; 16]) -> std::result::Result<(), TpmError> {
        // Same outcome as a provisioned user without a PIN (`pin::verify`).
        self.with_existing_user(uid, Err(TpmError::PolicyFailed), |ctx, srk, user| {
            pin::verify(ctx, srk, &user.store, pin_hash)
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

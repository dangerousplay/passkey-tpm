//! The boundary between the verified core and the TPM shell (`passkey-tpm-tpm`).
//!
//! The core decides *which* gate may be used; the TPM independently enforces the same
//! decision through key policies, so a bug on either side alone can't release a signature.

pub use passkey_tpm_wire::credid::{CredBlobs, CredProtect};
pub use passkey_tpm_wire::resident::ResidentEntry;

pub use crate::gates::GateKind;

/// Local user that owns a credential, taken from the caller's D-Bus credentials and never
/// from request data (TPM-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uid(pub u32);

/// SHA-256 of the relying party ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpIdHash(pub [u8; 32]);

/// Outcomes the core maps to CTAP status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    /// The TPM was cleared or the storage root key changed; every credential is lost.
    Reset,
    /// The TPM refused the policy (wrong user, wrong RP, wrong gate, or a forged ID).
    /// Reported to clients like an unknown credential, so it is not an oracle.
    PolicyFailed,
    /// The TPM is in dictionary-attack lockout.
    Lockout,
    /// The PIN gate's authorisation value did not match.
    WrongPin,
    /// Communication with the TPM failed.
    Unavailable,
}

/// TPM operations the core needs. Implemented by `passkey-tpm-tpm` and by test doubles.
pub trait TpmOps {
    /// Creates a credential key (and hmac-secret keys if requested) bound to `uid`'s gates
    /// and `rp`.
    ///
    /// # Errors
    /// [`TpmError`] on TPM failure.
    fn create_credential(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        protect: CredProtect,
        with_hmac: bool,
    ) -> Result<CredBlobs, TpmError>;

    /// Serialises `blobs` into a credential ID tagged for `uid` and `rp`.
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the user's state can't be loaded.
    fn credential_id(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        blobs: &CredBlobs,
    ) -> Result<Vec<u8>, TpmError>;

    /// Parses a credential ID from a relying party. `Ok(None)` if it isn't one of `uid`'s
    /// credentials for `rp` (wrong tag, foreign or malformed ID). Constant-time tag check.
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the user's state can't be loaded.
    fn open_credential_id(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        id: &[u8],
    ) -> Result<Option<CredBlobs>, TpmError>;

    /// The credential's P-256 public key `(x, y)`.
    ///
    /// # Errors
    /// [`TpmError::PolicyFailed`] if the blobs aren't a P-256 key.
    fn public_key(&mut self, blobs: &CredBlobs) -> Result<([u8; 32], [u8; 32]), TpmError>;

    /// ECDSA-P256 signature over `digest`, authorised through `gate`.
    /// Returns the DER-encoded signature.
    ///
    /// # Errors
    /// [`TpmError::PolicyFailed`] if `blobs` doesn't belong to `uid`/`rp` or `gate` isn't
    /// permitted for the credential.
    fn sign(
        &mut self,
        uid: Uid,
        blobs: &CredBlobs,
        rp: &RpIdHash,
        gate: GateKind,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, TpmError>;

    /// HMAC-SHA-256(CredRandom, salt) with the WithUV key for UV gates and the WithoutUV key
    /// for the presence gate.
    ///
    /// # Errors
    /// [`TpmError::PolicyFailed`] as for [`TpmOps::sign`].
    fn hmac(
        &mut self,
        uid: Uid,
        blobs: &CredBlobs,
        rp: &RpIdHash,
        gate: GateKind,
        salt: &[u8; 32],
    ) -> Result<[u8; 32], TpmError>;

    /// Replaces `uid`'s PIN gate secret. `old` is `None` when no PIN is set yet.
    ///
    /// # Errors
    /// [`TpmError::WrongPin`] if `old` doesn't match.
    fn change_pin(
        &mut self,
        uid: Uid,
        old: Option<&[u8; 16]>,
        new: &[u8; 16],
    ) -> Result<(), TpmError>;

    /// Verifies a PIN (`LEFT(SHA-256(PIN), 16)`). The TPM performs the comparison against
    /// the DA-protected PIN gate.
    ///
    /// # Errors
    /// [`TpmError::WrongPin`], [`TpmError::Lockout`], or [`TpmError::Unavailable`] if no PIN is set.
    fn verify_pin(&mut self, uid: Uid, pin_hash: &[u8; 16]) -> Result<(), TpmError>;

    /// Whether `uid` has set a PIN.
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the user's state can't be loaded.
    fn pin_is_set(&mut self, uid: Uid) -> Result<bool, TpmError>;

    /// Persisted CTAP `pinRetries` (8 when never set).
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the user's state can't be read.
    fn pin_retries(&mut self, uid: Uid) -> Result<u8, TpmError>;

    /// Persists CTAP `pinRetries` (written before every PIN check, CTAP 2.1 §6.5.5.7.2).
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the state can't be written.
    fn set_pin_retries(&mut self, uid: Uid, retries: u8) -> Result<(), TpmError>;

    /// The user's discoverable credentials (empty if none).
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the store can't be read or is corrupt.
    fn resident_entries(&mut self, uid: Uid) -> Result<Vec<ResidentEntry>, TpmError>;

    /// Replaces the user's discoverable credentials (atomic).
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the store can't be written.
    fn store_resident_entries(
        &mut self,
        uid: Uid,
        entries: &[ResidentEntry],
    ) -> Result<(), TpmError>;

    /// Revokes a credential ID: [`TpmOps::open_credential_id`] returns `None` for it from now
    /// on (credential management deleteCredential).
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] if the revocation can't be persisted.
    fn revoke_credential(&mut self, uid: Uid, id: &[u8]) -> Result<(), TpmError>;

    /// authenticatorReset for one user: removes their gates, PIN and discoverable
    /// credentials; every credential ID they hold stops working.
    ///
    /// # Errors
    /// [`TpmError::Unavailable`] on TPM or filesystem errors.
    fn reset_user(&mut self, uid: Uid) -> Result<(), TpmError>;

    /// Checks that the storage root key is the one credentials were created under.
    ///
    /// # Errors
    /// [`TpmError::Reset`] if the TPM was cleared.
    fn health(&mut self) -> Result<(), TpmError>;
}

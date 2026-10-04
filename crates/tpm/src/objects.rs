//! Conversions between TPM objects and the byte blobs stored in credential IDs and state files.

use passkey_tpm_core::tpm_iface::CredBlobs;
use passkey_tpm_wire::credid::KeyBlobs;
use sha2::{Digest as _, Sha256};
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::structures::{Auth, Private, Public};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;

use crate::error::{Error, Result};
use crate::srk::Srk;

/// TPM_ALG_SHA256 as it prefixes a Name.
const NAME_ALG_SHA256: [u8; 2] = [0x00, 0x0b];

/// Marshals a `TPM2_Create` result into blobs (`TPMT_PUBLIC`, `TPM2B_PRIVATE` body).
///
/// # Errors
/// Marshalling errors.
pub fn to_blobs(public: &Public, private: &Private) -> Result<KeyBlobs> {
    Ok(KeyBlobs {
        public: public.marshall()?,
        private: private.value().to_vec(),
    })
}

/// Inverse of [`to_blobs`].
///
/// # Errors
/// [`Error::Corrupt`] if the blobs aren't valid TPM structures.
pub fn from_blobs(blobs: &KeyBlobs) -> Result<(Public, Private)> {
    let public = Public::unmarshall(&blobs.public).map_err(|_| Error::Corrupt("public area"))?;
    let private =
        Private::try_from(blobs.private.clone()).map_err(|_| Error::Corrupt("private area"))?;
    Ok((public, private))
}

/// The TPM Name of an object: `nameAlg ‖ SHA-256(TPMT_PUBLIC)`. Our objects all use SHA-256.
#[must_use]
pub fn name_of(public_blob: &[u8]) -> Vec<u8> {
    let mut name = NAME_ALG_SHA256.to_vec();
    name.extend_from_slice(&Sha256::digest(public_blob));
    name
}

/// Loads `blobs` under the SRK and sets the object's authValue for later use.
///
/// # Errors
/// TPM errors, e.g. if the blobs were made on another TPM or were tampered with.
pub fn load(
    ctx: &mut Context,
    srk: &Srk,
    blobs: &KeyBlobs,
    auth: Option<&[u8]>,
) -> Result<KeyHandle> {
    let (public, private) = from_blobs(blobs)?;
    let handle = ctx.execute_with_nullauth_session(|ctx| ctx.load(srk.handle, private, public))?;
    if let Some(auth) = auth {
        let auth = Auth::try_from(auth.to_vec()).map_err(Error::from);
        if let Err(e) = auth.and_then(|a| Ok(ctx.tr_set_auth(ObjectHandle::from(handle), a)?)) {
            let _ = ctx.flush_context(ObjectHandle::from(handle));
            return Err(e);
        }
    }
    Ok(handle)
}

/// Flushes a loaded object, ignoring errors (used on cleanup paths).
pub fn flush(ctx: &mut Context, handle: KeyHandle) {
    let _ = ctx.flush_context(ObjectHandle::from(handle));
}

/// Returns `blobs`' credential key blobs (convenience for callers holding a [`CredBlobs`]).
#[must_use]
pub fn credential_key(blobs: &CredBlobs) -> &KeyBlobs {
    &blobs.key
}

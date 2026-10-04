//! Credential-ID tags: `HMAC-SHA-256(K_uid, rpIdHash ‖ body)[..16]` (MVP1-03).
//!
//! The tag tells the broker, before any gesture, whether an ID from a relying party is one
//! of this user's credentials for this RP (needed for excludeList and to avoid asking for a
//! fingerprint only to fail). It is not the security boundary: the TPM policy is.

use hmac::{Hmac, KeyInit, Mac};
use passkey_tpm_core::tpm_iface::{CredBlobs, RpIdHash};
use passkey_tpm_wire::credid::{self, TAG_LEN};
use sha2::Sha256;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

fn mac(key: &[u8; 32], rp: &RpIdHash, body: &[u8]) -> Result<HmacSha256> {
    let mut m = HmacSha256::new_from_slice(key).map_err(|_| Error::Corrupt("MAC key"))?;
    m.update(b"passkey-tpm/v1/credid");
    m.update(&rp.0);
    m.update(body);
    Ok(m)
}

/// Builds the credential ID for `blobs`.
///
/// # Errors
/// [`Error::Corrupt`] if the blobs don't fit in a credential ID.
pub fn seal(key: &[u8; 32], rp: &RpIdHash, blobs: &CredBlobs) -> Result<Vec<u8>> {
    let body = blobs
        .encode()
        .map_err(|_| Error::Corrupt("credential too large for an ID"))?;
    let full = mac(key, rp, &body)?.finalize().into_bytes();
    let tag: [u8; TAG_LEN] = full
        .get(..TAG_LEN)
        .and_then(|t| t.try_into().ok())
        .ok_or(Error::Corrupt("MAC length"))?;
    credid::join_id(&body, &tag).map_err(|_| Error::Corrupt("credential too large for an ID"))
}

/// Returns the blobs if `id` carries a valid tag for this key and RP, else `None`.
#[must_use]
pub fn open(key: &[u8; 32], rp: &RpIdHash, id: &[u8]) -> Option<CredBlobs> {
    let (body, tag) = credid::split_id(id).ok()?;
    mac(key, rp, body).ok()?.verify_truncated_left(&tag).ok()?;
    CredBlobs::decode(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use passkey_tpm_wire::credid::{CredProtect, KeyBlobs};

    fn blobs() -> CredBlobs {
        CredBlobs {
            protect: CredProtect::UvOptional,
            key: KeyBlobs {
                public: vec![1; 40],
                private: vec![2; 60],
            },
            hmac: None,
        }
    }

    #[test]
    fn opens_only_with_same_key_and_rp() {
        let rp = RpIdHash([1; 32]);
        let id = seal(&[9; 32], &rp, &blobs()).unwrap();
        assert_eq!(open(&[9; 32], &rp, &id), Some(blobs()));
        assert_eq!(open(&[8; 32], &rp, &id), None, "other user's key");
        assert_eq!(open(&[9; 32], &RpIdHash([2; 32]), &id), None, "other RP");
        let mut tampered = id.clone();
        tampered[3] ^= 1;
        assert_eq!(open(&[9; 32], &rp, &tampered), None, "tampered body");
        assert_eq!(open(&[9; 32], &rp, &[0; 5]), None, "garbage");
    }
}

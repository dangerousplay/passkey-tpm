//! Credential ID format, version 2.
//!
//! A non-discoverable credential ID carries the TPM-wrapped key blobs; relying parties
//! store it and hand it back on assertion. The TPM protects confidentiality and integrity of
//! the private blobs, and the key's policy binds it to the RP and the user (ADR 0003), so this
//! format holds no secrets and no rpId or uid.
//!
//! `credential ID = body ‖ tag`, where `tag` is a 16-byte MAC over `rpIdHash ‖ body` keyed
//! with a per-user secret held by the broker (computed in `passkey-tpm-tpm`). The tag lets the
//! broker recognise its own credentials for this user and RP before asking for a gesture; it
//! is an index, not the security boundary, which remains the TPM policy.
//!
//! Body:
//!
//! ```text
//! u8  version = 2
//! u8  flags      bits 0-1: credProtect level (1..=3), bit 2: hmac-secret keys present
//! TPM2B cred_key public    (u16 big-endian length + bytes)
//! TPM2B cred_key private
//! [TPM2B hmac_uv public, TPM2B hmac_uv private,
//!  TPM2B hmac_nouv public, TPM2B hmac_nouv private]   if bit 2 is set
//! ```

use crate::reader::{Reader, Truncated};

pub const VERSION: u8 = 2;
/// WebAuthn L3 limits credential IDs to 1023 bytes.
pub const MAX_LEN: usize = 1023;
/// Length of the trailing MAC tag.
pub const TAG_LEN: usize = 16;
/// Largest body that still fits in a credential ID with its tag.
pub const MAX_BODY_LEN: usize = MAX_LEN - TAG_LEN;

const PROTECT_MASK: u8 = 0b0000_0011;
const HMAC_FLAG: u8 = 0b0000_0100;
const KNOWN_FLAGS: u8 = PROTECT_MASK | HMAC_FLAG;

/// CTAP 2.1 credProtect policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredProtect {
    UvOptional = 1,
    UvOptionalWithCredIdList = 2,
    UvRequired = 3,
}

impl CredProtect {
    #[must_use]
    pub fn from_level(level: u8) -> Option<Self> {
        match level {
            1 => Some(Self::UvOptional),
            2 => Some(Self::UvOptionalWithCredIdList),
            3 => Some(Self::UvRequired),
            _ => None,
        }
    }

    #[must_use]
    pub fn level(self) -> u8 {
        self as u8
    }
}

/// A TPM object as returned by `TPM2_Create`: marshalled public area and wrapped private area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlobs {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

/// The two hmac-secret keys (CredRandomWithUV / CredRandomWithoutUV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacBlobs {
    pub with_uv: KeyBlobs,
    pub without_uv: KeyBlobs,
}

/// Everything a credential ID carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredBlobs {
    pub protect: CredProtect,
    pub key: KeyBlobs,
    pub hmac: Option<HmacBlobs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    TooLong,
    UnknownVersion,
    InvalidFlags,
    EmptyBlob,
    TrailingBytes,
}

impl From<Truncated> for DecodeError {
    fn from(_: Truncated) -> Self {
        Self::Truncated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// A blob is longer than `u16::MAX`, or the whole ID exceeds [`MAX_LEN`].
    TooLong,
    EmptyBlob,
}

impl CredBlobs {
    /// Serialises to a credential ID.
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if the result would exceed [`MAX_LEN`],
    /// [`EncodeError::EmptyBlob`] if any blob is empty.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut flags = self.protect.level();
        if self.hmac.is_some() {
            flags |= HMAC_FLAG;
        }
        let mut out = Vec::with_capacity(MAX_LEN);
        out.push(VERSION);
        out.push(flags);
        put_key(&mut out, &self.key)?;
        if let Some(hmac) = &self.hmac {
            put_key(&mut out, &hmac.with_uv)?;
            put_key(&mut out, &hmac.without_uv)?;
        }
        if out.len() > MAX_BODY_LEN {
            return Err(EncodeError::TooLong);
        }
        Ok(out)
    }

    /// Parses a credential ID received from a relying party.
    ///
    /// # Errors
    /// Any [`DecodeError`]; never panics on any input.
    pub fn decode(id: &[u8]) -> Result<Self, DecodeError> {
        if id.len() > MAX_BODY_LEN {
            return Err(DecodeError::TooLong);
        }
        let mut r = Reader::new(id);
        if r.u8()? != VERSION {
            return Err(DecodeError::UnknownVersion);
        }
        let flags = r.u8()?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(DecodeError::InvalidFlags);
        }
        let protect =
            CredProtect::from_level(flags & PROTECT_MASK).ok_or(DecodeError::InvalidFlags)?;
        let key = get_key(&mut r)?;
        let hmac = if flags & HMAC_FLAG != 0 {
            Some(HmacBlobs {
                with_uv: get_key(&mut r)?,
                without_uv: get_key(&mut r)?,
            })
        } else {
            None
        };
        if !r.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(CredBlobs { protect, key, hmac })
    }
}

/// Appends `tag` to an encoded body.
///
/// # Errors
/// [`EncodeError::TooLong`] if the result would exceed [`MAX_LEN`].
pub fn join_id(body: &[u8], tag: &[u8; TAG_LEN]) -> Result<Vec<u8>, EncodeError> {
    if body.len() > MAX_BODY_LEN {
        return Err(EncodeError::TooLong);
    }
    let mut id = Vec::with_capacity(MAX_LEN);
    id.extend_from_slice(body);
    id.extend_from_slice(tag);
    Ok(id)
}

/// Splits a credential ID into its body and tag without interpreting the body.
///
/// # Errors
/// [`DecodeError::TooLong`] above [`MAX_LEN`], [`DecodeError::Truncated`] below [`TAG_LEN`].
pub fn split_id(id: &[u8]) -> Result<(&[u8], [u8; TAG_LEN]), DecodeError> {
    if id.len() > MAX_LEN {
        return Err(DecodeError::TooLong);
    }
    let body_len = id
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(DecodeError::Truncated)?;
    let (body, tag) = id
        .split_at_checked(body_len)
        .ok_or(DecodeError::Truncated)?;
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| DecodeError::Truncated)?;
    Ok((body, tag))
}

fn put_key(out: &mut Vec<u8>, key: &KeyBlobs) -> Result<(), EncodeError> {
    put_tpm2b(out, &key.public)?;
    put_tpm2b(out, &key.private)
}

fn put_tpm2b(out: &mut Vec<u8>, blob: &[u8]) -> Result<(), EncodeError> {
    if blob.is_empty() {
        return Err(EncodeError::EmptyBlob);
    }
    let len = u16::try_from(blob.len()).map_err(|_| EncodeError::TooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(blob);
    Ok(())
}

fn get_key(r: &mut Reader<'_>) -> Result<KeyBlobs, DecodeError> {
    Ok(KeyBlobs {
        public: get_tpm2b(r)?,
        private: get_tpm2b(r)?,
    })
}

fn get_tpm2b(r: &mut Reader<'_>) -> Result<Vec<u8>, DecodeError> {
    let body = r.len16_prefixed()?;
    if body.is_empty() {
        return Err(DecodeError::EmptyBlob);
    }
    Ok(body.to_vec())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Bounded: Kani explores every byte string up to `N` bytes. Longer inputs are covered by
    /// the `credid_decode` fuzz target; the decoder's control flow does not depend on length
    /// beyond the prefixes exercised here.
    const N: usize = 14;

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_never_panics() {
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any_where(|l| *l <= N);
        let _ = CredBlobs::decode(&buf[..len]);
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn split_id_never_panics_and_keeps_all_bytes() {
        let buf: [u8; 18] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 18);
        if let Ok((body, tag)) = split_id(&buf[..len]) {
            assert_eq!(body.len() + TAG_LEN, len);
            assert_eq!(tag.len(), TAG_LEN);
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_accepts_only_valid_flags() {
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any_where(|l| *l <= N);
        if let Ok(blobs) = CredBlobs::decode(&buf[..len]) {
            assert!(buf[1] & !KNOWN_FLAGS == 0);
            assert_eq!(blobs.protect.level(), buf[1] & PROTECT_MASK);
            assert_eq!(blobs.hmac.is_some(), buf[1] & HMAC_FLAG != 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(public: &[u8], private: &[u8]) -> KeyBlobs {
        KeyBlobs {
            public: public.to_vec(),
            private: private.to_vec(),
        }
    }

    fn sample(hmac: bool) -> CredBlobs {
        CredBlobs {
            protect: CredProtect::UvRequired,
            key: key(&[1; 90], &[2; 160]),
            hmac: hmac.then(|| HmacBlobs {
                with_uv: key(&[3; 50], &[4; 96]),
                without_uv: key(&[5; 50], &[6; 96]),
            }),
        }
    }

    #[test]
    fn round_trips_with_and_without_hmac() {
        for hmac in [false, true] {
            let blobs = sample(hmac);
            assert_eq!(CredBlobs::decode(&blobs.encode().unwrap()), Ok(blobs));
        }
    }

    #[test]
    fn realistic_size_fits_webauthn_limit() {
        // P-256 TPMT_PUBLIC with a PolicyOR digest ≈ 122 B, wrapped private ≈ 126 B;
        // keyedHash public ≈ 80 B, private ≈ 94 B (to be confirmed by tpm T10 measurements).
        let blobs = CredBlobs {
            protect: CredProtect::UvOptional,
            key: key(&[0; 122], &[0; 126]),
            hmac: Some(HmacBlobs {
                with_uv: key(&[0; 80], &[0; 94]),
                without_uv: key(&[0; 80], &[0; 94]),
            }),
        };
        assert!(blobs.encode().unwrap().len() <= MAX_LEN);
    }

    #[test]
    fn rejects_malformed_ids() {
        let good = sample(false).encode().unwrap();
        let mut bad_version = good.clone();
        bad_version[0] = 9;
        assert_eq!(
            CredBlobs::decode(&bad_version),
            Err(DecodeError::UnknownVersion)
        );
        let mut bad_flags = good.clone();
        bad_flags[1] = 0x80 | 3;
        assert_eq!(
            CredBlobs::decode(&bad_flags),
            Err(DecodeError::InvalidFlags)
        );
        let mut zero_protect = good.clone();
        zero_protect[1] = 0;
        assert_eq!(
            CredBlobs::decode(&zero_protect),
            Err(DecodeError::InvalidFlags)
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            CredBlobs::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        assert_eq!(
            CredBlobs::decode(&good[..good.len() - 1]),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            CredBlobs::decode(&[VERSION, 1, 0, 0, 0, 1, 9]),
            Err(DecodeError::EmptyBlob)
        );
        assert_eq!(
            CredBlobs::decode(&vec![1; MAX_LEN + 1]),
            Err(DecodeError::TooLong)
        );
    }

    #[test]
    fn join_and_split_round_trip() {
        let body = sample(true).encode().unwrap();
        let id = join_id(&body, &[7; TAG_LEN]).unwrap();
        assert!(id.len() <= MAX_LEN);
        let (b, tag) = split_id(&id).unwrap();
        assert_eq!(b, body.as_slice());
        assert_eq!(tag, [7; TAG_LEN]);
        assert_eq!(CredBlobs::decode(b), Ok(sample(true)));
        assert_eq!(split_id(&[0; TAG_LEN - 1]), Err(DecodeError::Truncated));
        assert_eq!(split_id(&vec![0; MAX_LEN + 1]), Err(DecodeError::TooLong));
        assert_eq!(
            join_id(&vec![0; MAX_BODY_LEN + 1], &[0; TAG_LEN]),
            Err(EncodeError::TooLong)
        );
    }

    #[test]
    fn encode_rejects_oversize_and_empty() {
        let mut big = sample(true);
        big.key.private = vec![0; 900];
        assert_eq!(big.encode(), Err(EncodeError::TooLong));
        let mut empty = sample(false);
        empty.key.public.clear();
        assert_eq!(empty.encode(), Err(EncodeError::EmptyBlob));
    }

    fn arb_key() -> impl Strategy<Value = KeyBlobs> {
        (
            prop::collection::vec(any::<u8>(), 1..120),
            prop::collection::vec(any::<u8>(), 1..120),
        )
            .prop_map(|(public, private)| KeyBlobs { public, private })
    }

    proptest! {
        #[test]
        fn encode_decode_round_trip(level in 1u8..=3, k in arb_key(), h in prop::option::of((arb_key(), arb_key()))) {
            let blobs = CredBlobs {
                protect: CredProtect::from_level(level).unwrap(),
                key: k,
                hmac: h.map(|(with_uv, without_uv)| HmacBlobs { with_uv, without_uv }),
            };
            let id = blobs.encode().unwrap();
            prop_assert!(id.len() <= MAX_BODY_LEN);
            prop_assert_eq!(CredBlobs::decode(&id), Ok(blobs));
        }

        #[test]
        fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..1100)) {
            let _ = CredBlobs::decode(&bytes);
        }
    }
}

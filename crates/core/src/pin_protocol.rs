//! PIN/UV auth protocols 1 and 2 (MVP-2 task P).
//!
//! Authenticator side of CTAP 2.1 PS §6.5.4 (abstract interface), §6.5.6 (protocol one) and
//! §6.5.7 (protocol two):
//!
//! - [`KeyAgreement`]: the P-256 key agreement key (`regenerate`, `getPublicKey`).
//! - [`parse_platform_key`] + [`KeyAgreement::shared_secret`]: `decapsulate` (ECDH, then the
//!   protocol-specific `kdf`).
//! - [`SharedSecret`]: `encrypt`, `decrypt`, `authenticate`, `verify` keyed by the shared secret.
//! - [`authenticate_with_token`] / [`verify_with_token`]: the same MAC keyed by a
//!   pinUvAuthToken. Whether the token is "in use" (§6.5.2.1) is checked by the caller.
//!
//! This module is plain Rust (outside `verus!`); it holds no state besides key material, and
//! every secret is zeroized on drop.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::digest::generic_array::GenericArray;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use passkey_tpm_wire::cbor::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// AES block length (bytes).
const BLOCK: usize = 16;
/// Length of a P-256 field element / coordinate (bytes).
const COORD: usize = 32;
/// Signature length of protocol one (`LEFT(HMAC, 16)`).
const P1_SIG: usize = 16;
/// Signature length of protocol two (full HMAC-SHA-256).
const P2_SIG: usize = 32;
/// SHA-256 block size: HMAC keys up to this length are zero-padded to it (RFC 2104 §2).
const HMAC_BLOCK: usize = 64;
/// Attempts to draw a valid P-256 scalar; failure probability per draw is about 2^-32.
const KEYGEN_ATTEMPTS: usize = 16;

// COSE_Key labels and values (RFC 9052/9053; CTAP 2.1 §6.5.6 getPublicKey).
const COSE_KTY: i64 = 1;
const COSE_ALG: i64 = 3;
const COSE_CRV: i64 = -1;
const COSE_X: i64 = -2;
const COSE_Y: i64 = -3;
const KTY_EC2: i64 = 2;
const ALG_ECDH_ES_HKDF_256: i64 = -25;
const CRV_P256: i64 = 1;

/// Why a PIN/UV auth protocol operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// The platform COSE key is malformed: not a map, wrong `kty`/`alg`/`crv`, missing or
    /// extra parameters, or wrongly typed values.
    InvalidParameter,
    /// A coordinate, plaintext or ciphertext has the wrong length.
    InvalidLength,
    /// The platform point is not a valid P-256 point (off the curve, or the identity).
    InvalidPoint,
    /// A cryptographic primitive failed (e.g. HKDF output length, cipher setup).
    Crypto,
    /// The operating system RNG failed.
    Rng,
}

/// A PIN/UV auth protocol identifier (`pinUvAuthProtocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// PIN/UV auth protocol one (§6.5.6).
    One,
    /// PIN/UV auth protocol two (§6.5.7).
    Two,
}

impl Protocol {
    /// Maps the CTAP numeric identifier (1 or 2) to a protocol.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<Self> {
        match n {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            _ => None,
        }
    }

    /// The CTAP numeric identifier.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

/// The authenticator's key agreement key (a P-256 private key; zeroized on drop).
pub struct KeyAgreement {
    secret: SecretKey,
}

impl core::fmt::Debug for KeyAgreement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyAgreement").finish_non_exhaustive()
    }
}

impl KeyAgreement {
    /// `regenerate()`: a fresh random P-256 private key from the OS RNG.
    ///
    /// # Errors
    /// [`PinError::Rng`] if the OS RNG fails; [`PinError::Crypto`] if no valid scalar was drawn
    /// (practically impossible).
    pub fn generate() -> Result<Self, PinError> {
        for _ in 0..KEYGEN_ATTEMPTS {
            let mut bytes = Zeroizing::new([0u8; COORD]);
            getrandom::fill(bytes.as_mut_slice()).map_err(|_| PinError::Rng)?;
            // Rejects 0 and values >= n (rejection sampling keeps the scalar uniform).
            if let Ok(secret) = SecretKey::from_slice(bytes.as_slice()) {
                return Ok(Self { secret });
            }
        }
        Err(PinError::Crypto)
    }

    /// `getPublicKey()`: COSE_Key `{1: 2, 3: -25, -1: 1, -2: x, -3: y}` (§6.5.6).
    #[must_use]
    pub fn cose_public(&self) -> Value {
        let point = self.secret.public_key().to_encoded_point(false);
        let coord = |c: Option<&p256::FieldBytes>| c.map(|b| b.to_vec()).unwrap_or_default();
        Value::Map(vec![
            (Value::int_key(COSE_KTY), Value::int_key(KTY_EC2)),
            (
                Value::int_key(COSE_ALG),
                Value::int_key(ALG_ECDH_ES_HKDF_256),
            ),
            (Value::int_key(COSE_CRV), Value::int_key(CRV_P256)),
            (Value::int_key(COSE_X), Value::Bytes(coord(point.x()))),
            (Value::int_key(COSE_Y), Value::Bytes(coord(point.y()))),
        ])
    }

    /// `decapsulate(peerCoseKey)` after [`parse_platform_key`]: ECDH, then `kdf(Z)`.
    ///
    /// # Errors
    /// [`PinError::Crypto`] if HKDF fails (cannot happen for 32-byte outputs).
    pub fn shared_secret(
        &self,
        protocol: Protocol,
        platform: &PublicKey,
    ) -> Result<SharedSecret, PinError> {
        let z = self.ecdh_z(platform);
        kdf(protocol, &z)
    }

    /// Z: the 32-byte big-endian x-coordinate of the shared point (§6.5.6 `ecdh`).
    fn ecdh_z(&self, platform: &PublicKey) -> Zeroizing<[u8; COORD]> {
        let shared =
            p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), platform.as_affine());
        let mut z = Zeroizing::new([0u8; COORD]);
        z.copy_from_slice(shared.raw_secret_bytes().as_slice());
        z
    }
}

/// Parses the platform's `keyAgreement` COSE_Key into a validated P-256 point.
///
/// Strict per §6.5.5 / §6.5.6: the key must be exactly `{1: 2, 3: -25, -1: 1, -2: x, -3: y}`
/// ("MUST contain the optional alg parameter and MUST NOT contain any other optional
/// parameters"; parsed "as specified for getPublicKey"), with 32-byte coordinates forming a
/// point on the curve. The identity cannot be encoded with affine coordinates and is rejected.
///
/// # Errors
/// [`PinError::InvalidParameter`] for structural problems, [`PinError::InvalidLength`] for
/// coordinates that are not 32 bytes, [`PinError::InvalidPoint`] for points not on P-256.
pub fn parse_platform_key(v: &Value) -> Result<PublicKey, PinError> {
    let entries = v.as_map().ok_or(PinError::InvalidParameter)?;
    if entries.len() != 5 {
        return Err(PinError::InvalidParameter);
    }
    let int = |label: i64| {
        v.map_get(&Value::int_key(label))
            .and_then(Value::as_i64)
            .ok_or(PinError::InvalidParameter)
    };
    if int(COSE_KTY)? != KTY_EC2
        || int(COSE_ALG)? != ALG_ECDH_ES_HKDF_256
        || int(COSE_CRV)? != CRV_P256
    {
        return Err(PinError::InvalidParameter);
    }
    let bytes = |label: i64| {
        v.map_get(&Value::int_key(label))
            .and_then(Value::as_bytes)
            .ok_or(PinError::InvalidParameter)
    };
    let x = bytes(COSE_X)?;
    let y = bytes(COSE_Y)?;
    if x.len() != COORD || y.len() != COORD {
        return Err(PinError::InvalidLength);
    }
    // SEC1 uncompressed encoding: 0x04 || x || y. p256 checks the curve equation.
    let mut sec1 = Vec::with_capacity(1 + 2 * COORD);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| PinError::InvalidPoint)
}

/// The protocol-specific `kdf(Z)`.
fn kdf(protocol: Protocol, z: &[u8; COORD]) -> Result<SharedSecret, PinError> {
    match protocol {
        Protocol::One => {
            // §6.5.6: SHA-256(Z); the same 32 bytes key both AES and HMAC.
            let mut key = Zeroizing::new([0u8; COORD]);
            key.copy_from_slice(Sha256::digest(z).as_slice());
            Ok(SharedSecret {
                protocol,
                hmac_key: key.clone(),
                aes_key: key,
            })
        }
        Protocol::Two => {
            // §6.5.7: two separate HKDF-SHA-256 invocations (salt = 32 zero bytes, L = 32).
            let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
            let mut hmac_key = Zeroizing::new([0u8; COORD]);
            let mut aes_key = Zeroizing::new([0u8; COORD]);
            hk.expand(b"CTAP2 HMAC key", hmac_key.as_mut_slice())
                .map_err(|_| PinError::Crypto)?;
            hk.expand(b"CTAP2 AES key", aes_key.as_mut_slice())
                .map_err(|_| PinError::Crypto)?;
            Ok(SharedSecret {
                protocol,
                hmac_key,
                aes_key,
            })
        }
    }
}

/// HMAC-SHA-256 keyed with a 32-byte key, built infallibly.
///
/// HMAC zero-pads keys shorter than the hash block size (RFC 2104 §2), so padding here and
/// using the block-sized constructor is identical to `new_from_slice` (checked in tests).
fn hmac_32(key: &[u8; 32]) -> HmacSha256 {
    let mut block = Zeroizing::new([0u8; HMAC_BLOCK]);
    for (dst, src) in block.iter_mut().zip(key.iter()) {
        *dst = *src;
    }
    <HmacSha256 as KeyInit>::new(GenericArray::from_slice(block.as_slice()))
}

fn mac(protocol: Protocol, key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let mut m = hmac_32(key);
    m.update(message);
    let full = m.finalize().into_bytes();
    match protocol {
        Protocol::One => full.iter().take(P1_SIG).copied().collect(),
        Protocol::Two => full.to_vec(),
    }
}

fn mac_verify(protocol: Protocol, key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let mut m = hmac_32(key);
    m.update(message);
    match protocol {
        // `verify_truncated_left` accepts any length in 1..=32, so pin it to 16 first.
        Protocol::One => signature.len() == P1_SIG && m.verify_truncated_left(signature).is_ok(),
        Protocol::Two => signature.len() == P2_SIG && m.verify_slice(signature).is_ok(),
    }
}

/// The shared secret of one key agreement (zeroized on drop).
///
/// Protocol one uses the same 32-byte key for AES and HMAC; protocol two splits it into the
/// HMAC key (first 32 bytes of the §6.5.7 `kdf` output) and the AES key (last 32 bytes).
pub struct SharedSecret {
    protocol: Protocol,
    hmac_key: Zeroizing<[u8; 32]>,
    aes_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl SharedSecret {
    /// The protocol this secret was derived for.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// `encrypt(key, demPlaintext)`: protocol one AES-256-CBC with an all-zero IV; protocol two
    /// AES-256-CBC with a fresh random IV, returned as `iv || ct`. No padding.
    ///
    /// # Errors
    /// [`PinError::InvalidLength`] if the plaintext is not a multiple of 16 bytes;
    /// [`PinError::Rng`] if the IV cannot be drawn.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, PinError> {
        if !plaintext.len().is_multiple_of(BLOCK) {
            return Err(PinError::InvalidLength);
        }
        let mut iv = [0u8; BLOCK];
        if self.protocol == Protocol::Two {
            getrandom::fill(&mut iv).map_err(|_| PinError::Rng)?;
        }
        let enc = cbc::Encryptor::<Aes256>::new_from_slices(self.aes_key.as_slice(), &iv)
            .map_err(|_| PinError::Crypto)?;
        let ct = enc.encrypt_padded_vec_mut::<NoPadding>(plaintext);
        Ok(match self.protocol {
            Protocol::One => ct,
            Protocol::Two => {
                let mut out = Vec::with_capacity(BLOCK.saturating_add(ct.len()));
                out.extend_from_slice(&iv);
                out.extend_from_slice(&ct);
                out
            }
        })
    }

    /// `decrypt(key, demCiphertext)`. Protocol two splits off the 16-byte IV prefix.
    ///
    /// # Errors
    /// [`PinError::InvalidLength`] if the ciphertext (after the IV, for protocol two) is not a
    /// multiple of 16 bytes, or a protocol-two input is shorter than 16 bytes.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, PinError> {
        let (iv, ct) = match self.protocol {
            Protocol::One => ([0u8; BLOCK], ciphertext),
            Protocol::Two => {
                let (iv, ct) = ciphertext
                    .split_first_chunk::<BLOCK>()
                    .ok_or(PinError::InvalidLength)?;
                (*iv, ct)
            }
        };
        if !ct.len().is_multiple_of(BLOCK) {
            return Err(PinError::InvalidLength);
        }
        let dec = cbc::Decryptor::<Aes256>::new_from_slices(self.aes_key.as_slice(), &iv)
            .map_err(|_| PinError::Crypto)?;
        dec.decrypt_padded_vec_mut::<NoPadding>(ct)
            .map(Zeroizing::new)
            .map_err(|_| PinError::InvalidLength)
    }

    /// `authenticate(key, message)`: HMAC-SHA-256 with the HMAC key; protocol one keeps the
    /// first 16 bytes, protocol two all 32.
    #[must_use]
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        mac(self.protocol, &self.hmac_key, message)
    }

    /// `verify(key, message, signature)` in constant time. The signature must be exactly 16
    /// (protocol one) or 32 (protocol two) bytes; any other length fails.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        mac_verify(self.protocol, &self.hmac_key, message, signature)
    }
}

/// `authenticate(pinUvAuthToken, message)` (e.g. a pinUvAuthParam over clientDataHash).
#[must_use]
pub fn authenticate_with_token(protocol: Protocol, token: &[u8; 32], message: &[u8]) -> Vec<u8> {
    mac(protocol, token, message)
}

/// `verify(pinUvAuthToken, message, signature)` in constant time, without the "in use" check
/// (the caller owns the token state).
#[must_use]
pub fn verify_with_token(
    protocol: Protocol,
    token: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> bool {
    mac_verify(protocol, token, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Minimal platform side (§6.5.4 platform interface): `encapsulate` = fresh key + ECDH.
    struct Platform {
        key: KeyAgreement,
        secret: SharedSecret,
    }

    fn encapsulate(protocol: Protocol, authenticator_cose: &Value) -> Platform {
        let key = KeyAgreement::generate().unwrap();
        let peer = parse_platform_key(authenticator_cose).unwrap();
        let secret = key.shared_secret(protocol, &peer).unwrap();
        Platform { key, secret }
    }

    /// Authenticator key, platform, and the authenticator's view of the shared secret.
    fn session(protocol: Protocol) -> (KeyAgreement, Platform, SharedSecret) {
        let auth = KeyAgreement::generate().unwrap();
        let platform = encapsulate(protocol, &auth.cose_public());
        let platform_pub = parse_platform_key(&platform.key.cose_public()).unwrap();
        let secret = auth.shared_secret(protocol, &platform_pub).unwrap();
        (auth, platform, secret)
    }

    fn cose(entries: Vec<(i64, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::int_key(k), v))
                .collect(),
        )
    }

    fn valid_entries(k: &KeyAgreement) -> Vec<(i64, Value)> {
        let c = k.cose_public();
        vec![
            (1, Value::int_key(2)),
            (3, Value::int_key(-25)),
            (-1, Value::int_key(1)),
            (-2, c.map_get(&Value::int_key(-2)).unwrap().clone()),
            (-3, c.map_get(&Value::int_key(-3)).unwrap().clone()),
        ]
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    const BOTH: [Protocol; 2] = [Protocol::One, Protocol::Two];

    #[test]
    fn protocol_ids() {
        assert_eq!(Protocol::from_u64(1), Some(Protocol::One));
        assert_eq!(Protocol::from_u64(2), Some(Protocol::Two));
        assert_eq!(Protocol::from_u64(0), None);
        assert_eq!(Protocol::from_u64(3), None);
        assert_eq!(Protocol::One.as_u64(), 1);
        assert_eq!(Protocol::Two.as_u64(), 2);
    }

    #[test]
    fn cose_public_shape_and_cbor_round_trip() {
        let k = KeyAgreement::generate().unwrap();
        let c = k.cose_public();
        let get = |l: i64| c.map_get(&Value::int_key(l)).unwrap();
        assert_eq!(c.as_map().unwrap().len(), 5);
        assert_eq!(get(1).as_i64(), Some(2));
        assert_eq!(get(3).as_i64(), Some(-25));
        assert_eq!(get(-1).as_i64(), Some(1));
        assert_eq!(get(-2).as_bytes().unwrap().len(), 32);
        assert_eq!(get(-3).as_bytes().unwrap().len(), 32);
        let wire = passkey_tpm_wire::cbor::encode(&c);
        let decoded = passkey_tpm_wire::cbor::decode(&wire).unwrap();
        assert_eq!(parse_platform_key(&decoded).unwrap(), k.secret.public_key());
    }

    #[test]
    fn both_sides_derive_the_same_secret() {
        for p in BOTH {
            let (_, platform, secret) = session(p);
            assert_eq!(*platform.secret.hmac_key, *secret.hmac_key);
            assert_eq!(*platform.secret.aes_key, *secret.aes_key);
            assert_eq!(secret.protocol(), p);
        }
    }

    #[test]
    fn protocol_one_kdf_is_sha256_of_z() {
        let a = KeyAgreement::generate().unwrap();
        let b = KeyAgreement::generate().unwrap();
        let z = a.ecdh_z(&b.secret.public_key());
        // Z cross-check: the other side, and a raw scalar multiplication.
        assert_eq!(*z, *b.ecdh_z(&a.secret.public_key()));
        let point = (b.secret.public_key().to_projective() * *a.secret.to_nonzero_scalar())
            .to_affine()
            .to_encoded_point(false);
        assert_eq!(point.x().unwrap().as_slice(), z.as_slice());
        let s = a
            .shared_secret(Protocol::One, &b.secret.public_key())
            .unwrap();
        let expected: [u8; 32] = Sha256::digest(z.as_slice()).into();
        assert_eq!(*s.hmac_key, expected);
        assert_eq!(*s.aes_key, expected);
    }

    /// RFC 5869 §2.2 (extract) and §2.3 (expand, one block) computed by hand with HMAC.
    fn hkdf_by_hand(z: &[u8], info: &[u8]) -> [u8; 32] {
        let mut ext = <HmacSha256 as Mac>::new_from_slice(&[0u8; 32]).unwrap();
        ext.update(z);
        let prk = ext.finalize().into_bytes();
        let mut exp = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
        exp.update(info);
        exp.update(&[0x01]);
        exp.finalize().into_bytes().into()
    }

    #[test]
    fn protocol_two_kdf_matches_hand_hkdf() {
        let a = KeyAgreement::generate().unwrap();
        let b = KeyAgreement::generate().unwrap();
        let z = a.ecdh_z(&b.secret.public_key());
        let s = a
            .shared_secret(Protocol::Two, &b.secret.public_key())
            .unwrap();
        assert_eq!(*s.hmac_key, hkdf_by_hand(z.as_slice(), b"CTAP2 HMAC key"));
        assert_eq!(*s.aes_key, hkdf_by_hand(z.as_slice(), b"CTAP2 AES key"));
        assert_ne!(*s.hmac_key, *s.aes_key);
    }

    #[test]
    fn hand_hkdf_matches_rfc5869_case_3() {
        // RFC 5869 Test Case 3: no salt (= HashLen zero bytes, like CTAP's 32-zero salt),
        // empty info. Pins the hand implementation used above to a published vector.
        let ikm = [0x0bu8; 22];
        let expected = hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut okm)
            .unwrap();
        assert_eq!(okm.to_vec(), expected);
        assert_eq!(hkdf_by_hand(&ikm, &[]).to_vec(), expected[..32].to_vec());
    }

    #[test]
    fn aes256_cbc_sp800_38a_vector() {
        // NIST SP 800-38A F.2.6 CBC-AES256.Decrypt (first two blocks), as protocol two iv || ct.
        let key: [u8; 32] = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .try_into()
            .unwrap();
        let s = SharedSecret {
            protocol: Protocol::Two,
            hmac_key: Zeroizing::new([0u8; 32]),
            aes_key: Zeroizing::new(key),
        };
        let mut input = hex("000102030405060708090a0b0c0d0e0f");
        input.extend(hex(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d",
        ));
        assert_eq!(
            s.decrypt(&input).unwrap().to_vec(),
            hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        );
    }

    #[test]
    fn protocol_one_uses_zero_iv() {
        let (_, platform, secret) = session(Protocol::One);
        let pt = [0x42u8; 32];
        let ct = platform.secret.encrypt(&pt).unwrap();
        assert_eq!(ct.len(), 32);
        assert_eq!(ct, platform.secret.encrypt(&pt).unwrap());
        let manual =
            cbc::Encryptor::<Aes256>::new_from_slices(secret.aes_key.as_slice(), &[0u8; 16])
                .unwrap()
                .encrypt_padded_vec_mut::<NoPadding>(&pt);
        assert_eq!(ct, manual);
    }

    #[test]
    fn protocol_two_uses_fresh_iv() {
        let (_, platform, secret) = session(Protocol::Two);
        let pt = [0x42u8; 16];
        let a = platform.secret.encrypt(&pt).unwrap();
        let b = platform.secret.encrypt(&pt).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a[..16], b[..16], "IVs must differ");
        assert_ne!(a[16..], b[16..]);
        assert_eq!(secret.decrypt(&a).unwrap().as_slice(), pt);
        assert_eq!(secret.decrypt(&b).unwrap().as_slice(), pt);
    }

    #[test]
    fn encrypt_rejects_unaligned_plaintext() {
        for p in BOTH {
            let (_, platform, _) = session(p);
            for len in [1usize, 15, 17, 63] {
                assert_eq!(
                    platform.secret.encrypt(&vec![0; len]),
                    Err(PinError::InvalidLength)
                );
            }
            assert!(platform.secret.encrypt(&[]).is_ok());
        }
    }

    #[test]
    fn decrypt_length_checks() {
        let (_, _, s1) = session(Protocol::One);
        for len in [1usize, 15, 17, 33] {
            assert_eq!(s1.decrypt(&vec![0; len]), Err(PinError::InvalidLength));
        }
        assert!(s1.decrypt(&[]).unwrap().is_empty());
        let (_, _, s2) = session(Protocol::Two);
        for len in [0usize, 1, 15, 17, 31, 33] {
            assert_eq!(s2.decrypt(&vec![0; len]), Err(PinError::InvalidLength));
        }
        // IV only: empty plaintext.
        assert!(s2.decrypt(&[0; 16]).unwrap().is_empty());
    }

    #[test]
    fn tampered_ciphertext_changes_plaintext() {
        for p in BOTH {
            let (_, platform, secret) = session(p);
            let mut pin = [0u8; 64];
            pin[..4].copy_from_slice(b"1234");
            let mut ct = platform.secret.encrypt(&pin).unwrap();
            ct[0] ^= 1;
            assert_ne!(secret.decrypt(&ct).unwrap().as_slice(), pin);
        }
    }

    #[test]
    fn authenticate_lengths_and_tamper() {
        for (p, len) in [(Protocol::One, 16), (Protocol::Two, 32)] {
            let (_, platform, secret) = session(p);
            let msg = b"newPinEnc || pinHashEnc";
            let sig = platform.secret.authenticate(msg);
            assert_eq!(sig.len(), len);
            assert!(secret.verify(msg, &sig));
            assert!(!secret.verify(b"other", &sig));
            let mut bad = sig.clone();
            bad[len - 1] ^= 0x80;
            assert!(!secret.verify(msg, &bad));
            assert!(!secret.verify(msg, &sig[..len - 1]));
            assert!(!secret.verify(msg, &[]));
            let mut long = sig.clone();
            long.push(0);
            assert!(!secret.verify(msg, &long));
        }
    }

    #[test]
    fn protocol_one_requires_exactly_16_bytes() {
        let (_, _, s) = session(Protocol::One);
        let full = mac(Protocol::Two, &s.hmac_key, b"m");
        assert!(
            !s.verify(b"m", &full),
            "full 32-byte HMAC is not a p1 signature"
        );
        assert!(!s.verify(b"m", &full[..8]));
        assert!(s.verify(b"m", &full[..16]));
    }

    #[test]
    fn padded_hmac_key_matches_new_from_slice() {
        let key: [u8; 32] = core::array::from_fn(|i| u8::try_from(i + 1).unwrap());
        for msg in [&b""[..], b"abc", &[0xcd; 200]] {
            let mut m = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            m.update(msg);
            let expected = m.finalize().into_bytes().to_vec();
            assert_eq!(authenticate_with_token(Protocol::Two, &key, msg), expected);
            assert_eq!(
                authenticate_with_token(Protocol::One, &key, msg),
                expected[..16].to_vec()
            );
        }
    }

    #[test]
    fn token_helpers() {
        let token = [0xa5u8; 32];
        let cdh = [0x11u8; 32];
        for (p, len) in [(Protocol::One, 16), (Protocol::Two, 32)] {
            let sig = authenticate_with_token(p, &token, &cdh);
            assert_eq!(sig.len(), len);
            assert!(verify_with_token(p, &token, &cdh, &sig));
            assert!(!verify_with_token(p, &[0u8; 32], &cdh, &sig));
            assert!(!verify_with_token(p, &token, &[0u8; 32], &sig));
            assert!(!verify_with_token(p, &token, &cdh, &sig[1..]));
        }
    }

    #[test]
    fn invalid_cose_keys() {
        let k = KeyAgreement::generate().unwrap();
        assert!(parse_platform_key(&cose(valid_entries(&k))).is_ok());

        let with = |label: i64, v: Value| {
            let mut e = valid_entries(&k);
            for (l, val) in &mut e {
                if *l == label {
                    *val = v.clone();
                }
            }
            cose(e)
        };
        let without = |label: i64| {
            cose(
                valid_entries(&k)
                    .into_iter()
                    .filter(|(l, _)| *l != label)
                    .collect(),
            )
        };
        let param = Err(PinError::InvalidParameter);

        assert_eq!(parse_platform_key(&with(1, Value::int_key(1))), param);
        assert_eq!(parse_platform_key(&with(3, Value::int_key(-7))), param);
        assert_eq!(parse_platform_key(&with(-1, Value::int_key(2))), param);
        assert_eq!(
            parse_platform_key(&with(1, Value::Text("EC2".into()))),
            param
        );
        assert_eq!(parse_platform_key(&with(-2, Value::int_key(5))), param);
        for label in [1, 3, -1, -2, -3] {
            assert_eq!(parse_platform_key(&without(label)), param);
        }
        let mut extra = valid_entries(&k);
        extra.push((2, Value::Bytes(vec![1])));
        assert_eq!(parse_platform_key(&cose(extra)), param);
        assert_eq!(parse_platform_key(&Value::Array(vec![])), param);

        let len = Err(PinError::InvalidLength);
        assert_eq!(
            parse_platform_key(&with(-2, Value::Bytes(vec![1; 31]))),
            len
        );
        assert_eq!(
            parse_platform_key(&with(-3, Value::Bytes(vec![1; 33]))),
            len
        );

        let point = Err(PinError::InvalidPoint);
        // Off-curve: flip a bit of y.
        let c = k.cose_public();
        let mut y = c
            .map_get(&Value::int_key(-3))
            .unwrap()
            .as_bytes()
            .unwrap()
            .to_vec();
        y[31] ^= 1;
        assert_eq!(parse_platform_key(&with(-3, Value::Bytes(y))), point);
        // (0, 0) is not on P-256 (b != 0); the identity has no affine encoding.
        let zero = cose(vec![
            (1, Value::int_key(2)),
            (3, Value::int_key(-25)),
            (-1, Value::int_key(1)),
            (-2, Value::Bytes(vec![0; 32])),
            (-3, Value::Bytes(vec![0; 32])),
        ]);
        assert_eq!(parse_platform_key(&zero), point);
        // x >= p is not a canonical field element.
        assert_eq!(
            parse_platform_key(&with(-2, Value::Bytes(vec![0xff; 32]))),
            point
        );
    }

    #[test]
    fn regenerated_keys_differ() {
        let a = KeyAgreement::generate().unwrap();
        let b = KeyAgreement::generate().unwrap();
        assert_ne!(a.cose_public(), b.cose_public());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn prop_round_trip(
            blocks in 0usize..5,
            fill in any::<u8>(),
            msg in proptest::collection::vec(any::<u8>(), 0..128),
            two in any::<bool>(),
        ) {
            let p = if two { Protocol::Two } else { Protocol::One };
            let (_, platform, secret) = session(p);
            let pt = vec![fill; blocks * 16];
            let ct = platform.secret.encrypt(&pt).unwrap();
            prop_assert_eq!(secret.decrypt(&ct).unwrap().to_vec(), pt.clone());
            // Authenticator -> platform too (e.g. the encrypted pinUvAuthToken).
            let ct2 = secret.encrypt(&pt).unwrap();
            prop_assert_eq!(platform.secret.decrypt(&ct2).unwrap().to_vec(), pt);
            let sig = platform.secret.authenticate(&msg);
            prop_assert!(secret.verify(&msg, &sig));
        }

        #[test]
        fn prop_bit_flip_fails_verify(
            msg in proptest::collection::vec(any::<u8>(), 1..64),
            idx in any::<prop::sample::Index>(),
            bit in 0u8..8,
            two in any::<bool>(),
            flip_sig in any::<bool>(),
        ) {
            let p = if two { Protocol::Two } else { Protocol::One };
            let (_, platform, secret) = session(p);
            let mut m = msg.clone();
            let mut sig = platform.secret.authenticate(&msg);
            if flip_sig {
                let i = idx.index(sig.len());
                sig[i] ^= 1 << bit;
            } else {
                let i = idx.index(m.len());
                m[i] ^= 1 << bit;
            }
            prop_assert!(!secret.verify(&m, &sig));
        }

        #[test]
        fn prop_wrong_length_signature_rejected(
            extra in 1usize..32,
            shorter in any::<bool>(),
            msg in proptest::collection::vec(any::<u8>(), 0..32),
            two in any::<bool>(),
        ) {
            let p = if two { Protocol::Two } else { Protocol::One };
            let token = [3u8; 32];
            let good = authenticate_with_token(p, &token, &msg);
            let full = authenticate_with_token(Protocol::Two, &token, &msg);
            // A prefix or extension of the right MAC with any wrong length must fail.
            let mut sig = full.clone();
            sig.extend(std::iter::repeat_n(0u8, extra));
            if shorter {
                sig.truncate(good.len().saturating_sub(extra % good.len()).max(1));
            }
            prop_assume!(sig.len() != good.len());
            prop_assert!(!verify_with_token(p, &token, &msg, &sig));
        }

        #[test]
        fn prop_parse_never_panics(
            x in proptest::collection::vec(any::<u8>(), 0..40),
            y in proptest::collection::vec(any::<u8>(), 0..40),
        ) {
            let v = cose(vec![
                (1, Value::int_key(2)),
                (3, Value::int_key(-25)),
                (-1, Value::int_key(1)),
                (-2, Value::Bytes(x)),
                (-3, Value::Bytes(y)),
            ]);
            let _ = parse_platform_key(&v);
        }
    }
}

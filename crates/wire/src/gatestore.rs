//! Per-user gate state file `gates.v1` (ADR 0003, AD-013).
//!
//! Stored by the broker under `/var/lib/passkey-tpm/<uid>/`, readable only by the
//! `passkey-tpm` system user. Every gate is an NV index (so using it needs no `TPM2_Load`);
//! the file holds their indexes and authorisation values, the Argon2 salt for the PIN, the
//! credential-ID MAC key and the pinned SRK Name.
//!
//! ```text
//! b"PKTG"  magic
//! u8       version: 1, or 2 while a PIN change is pending
//! u32      PIN gate NV index (big-endian)
//! [u8;32]  Argon2id salt
//! u8       PIN state: 0 = no PIN set yet (followed by [u8;32] bootstrap authValue), 1 = set
//! u32      UV gate NV index,  [u8;32] UV gate authValue
//! u32      UP gate NV index,  [u8;32] UP gate authValue
//! [u8;32]  credential-ID MAC key (K_uid)
//! TPM2B    SRK Name
//! version 2 only:
//! [u8;32]  new Argon2id salt, [u8;32] new PIN gate authValue (pending PIN change)
//! ```
//!
//! A PIN change redefines the PIN NV index (AD-011). The broker writes the new values as a
//! pending change *before* touching the index and clears it afterwards, so a crash at any
//! point leaves a file from which the change can be completed (HARD-06). Files without a
//! pending change keep version 1; a reader that doesn't know version 2 fails closed.

use core::fmt;

use zeroize::Zeroizing;

use crate::reader::{Reader, Truncated};

pub const MAGIC: [u8; 4] = *b"PKTG";
pub const VERSION: u8 = 1;
/// Version of a file that carries a [`PendingPin`].
pub const VERSION_PENDING_PIN: u8 = 2;
/// Generous upper bound; real files are about 250 bytes.
pub const MAX_LEN: usize = 1024;

/// A 32-byte secret, wiped from memory on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthValue(pub Zeroizing<[u8; 32]>);

impl fmt::Debug for AuthValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthValue(<redacted>)")
    }
}

/// An NV-index gate and its authorisation value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    pub nv_index: u32,
    pub auth: AuthValue,
}

/// A PIN change persisted before the PIN NV index is redefined with `auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPin {
    /// Argon2id salt of the new PIN.
    pub salt: [u8; 32],
    /// The PIN gate authValue derived from the new PIN.
    pub auth: AuthValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateStore {
    pub pin_nv_index: u32,
    pub pin_salt: [u8; 32],
    /// Random authValue the PIN gate was defined with, kept until the first setPIN.
    /// Never a known constant: anyone with TPM access could otherwise satisfy it.
    pub pin_bootstrap: Option<AuthValue>,
    pub uv: Gate,
    pub up: Gate,
    /// Per-user key for credential-ID tags (recognising own credentials before a gesture).
    pub cred_mac_key: AuthValue,
    pub srk_name: Vec<u8>,
    /// A PIN change that was started but not yet confirmed complete.
    pub pending_pin: Option<PendingPin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    TooLong,
    BadMagic,
    UnknownVersion,
    EmptyField,
    InvalidPinState,
    TrailingBytes,
}

impl From<Truncated> for DecodeError {
    fn from(_: Truncated) -> Self {
        Self::Truncated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    TooLong,
    EmptyField,
}

fn secret(r: &mut Reader<'_>) -> Result<AuthValue, DecodeError> {
    Ok(AuthValue(Zeroizing::new(array(r.take(32)?)?)))
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], DecodeError> {
    bytes.try_into().map_err(|_| DecodeError::Truncated)
}

fn u32_be(r: &mut Reader<'_>) -> Result<u32, DecodeError> {
    Ok(u32::from_be_bytes(array(r.take(4)?)?))
}

impl GateStore {
    /// Serialises the store. The returned buffer contains secrets and is wiped on drop.
    ///
    /// # Errors
    /// [`EncodeError`] if the SRK Name is empty or too long.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, EncodeError> {
        let mut out = Zeroizing::new(Vec::with_capacity(320));
        out.extend_from_slice(&MAGIC);
        out.push(if self.pending_pin.is_some() {
            VERSION_PENDING_PIN
        } else {
            VERSION
        });
        out.extend_from_slice(&self.pin_nv_index.to_be_bytes());
        out.extend_from_slice(&self.pin_salt);
        match &self.pin_bootstrap {
            Some(auth) => {
                out.push(0);
                out.extend_from_slice(auth.0.as_slice());
            }
            None => out.push(1),
        }
        for gate in [&self.uv, &self.up] {
            out.extend_from_slice(&gate.nv_index.to_be_bytes());
            out.extend_from_slice(gate.auth.0.as_slice());
        }
        out.extend_from_slice(self.cred_mac_key.0.as_slice());
        if self.srk_name.is_empty() {
            return Err(EncodeError::EmptyField);
        }
        let len = u16::try_from(self.srk_name.len()).map_err(|_| EncodeError::TooLong)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.srk_name);
        if let Some(pending) = &self.pending_pin {
            out.extend_from_slice(&pending.salt);
            out.extend_from_slice(pending.auth.0.as_slice());
        }
        if out.len() > MAX_LEN {
            return Err(EncodeError::TooLong);
        }
        Ok(out)
    }

    /// Parses a store read from disk. A corrupt file is an error, never an empty store.
    ///
    /// # Errors
    /// Any [`DecodeError`]; never panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_LEN {
            return Err(DecodeError::TooLong);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != MAGIC.as_slice() {
            return Err(DecodeError::BadMagic);
        }
        let version = r.u8()?;
        if version != VERSION && version != VERSION_PENDING_PIN {
            return Err(DecodeError::UnknownVersion);
        }
        let pin_nv_index = u32_be(&mut r)?;
        let pin_salt = array(r.take(32)?)?;
        let pin_bootstrap = match r.u8()? {
            0 => Some(secret(&mut r)?),
            1 => None,
            _ => return Err(DecodeError::InvalidPinState),
        };
        let uv = Gate {
            nv_index: u32_be(&mut r)?,
            auth: secret(&mut r)?,
        };
        let up = Gate {
            nv_index: u32_be(&mut r)?,
            auth: secret(&mut r)?,
        };
        let cred_mac_key = secret(&mut r)?;
        let srk_name = r.len16_prefixed()?.to_vec();
        if srk_name.is_empty() {
            return Err(DecodeError::EmptyField);
        }
        let pending_pin = if version == VERSION_PENDING_PIN {
            Some(PendingPin {
                salt: array(r.take(32)?)?,
                auth: secret(&mut r)?,
            })
        } else {
            None
        };
        if !r.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(GateStore {
            pin_nv_index,
            pin_salt,
            pin_bootstrap,
            uv,
            up,
            cred_mac_key,
            srk_name,
            pending_pin,
        })
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    const N: usize = 12;

    #[kani::proof]
    #[kani::unwind(14)]
    fn decode_never_panics() {
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any_where(|l| *l <= N);
        let _ = GateStore::decode(&buf[..len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn secret(b: u8) -> AuthValue {
        AuthValue(Zeroizing::new([b; 32]))
    }

    fn sample() -> GateStore {
        GateStore {
            pin_nv_index: 0x0150_0001,
            pin_salt: [9; 32],
            pin_bootstrap: Some(secret(8)),
            uv: Gate {
                nv_index: 0x0150_0002,
                auth: secret(3),
            },
            up: Gate {
                nv_index: 0x0150_0003,
                auth: secret(4),
            },
            cred_mac_key: secret(0x77),
            srk_name: vec![0, 0x0b, 7, 7, 7],
            pending_pin: None,
        }
    }

    #[test]
    fn round_trip() {
        let store = sample();
        assert_eq!(
            GateStore::decode(&store.encode().unwrap()),
            Ok(store.clone())
        );
        let pin_set = GateStore {
            pin_bootstrap: None,
            ..store
        };
        assert_eq!(GateStore::decode(&pin_set.encode().unwrap()), Ok(pin_set));
    }

    #[test]
    fn pending_pin_change_round_trips_as_version_2() {
        let store = GateStore {
            pending_pin: Some(PendingPin {
                salt: [5; 32],
                auth: secret(6),
            }),
            ..sample()
        };
        let bytes = store.encode().unwrap();
        assert_eq!(bytes[4], VERSION_PENDING_PIN);
        assert_eq!(GateStore::decode(&bytes), Ok(store.clone()));
        // Without the pending change the file is version 1 again, 64 bytes shorter.
        let done = GateStore {
            pending_pin: None,
            ..store
        };
        let v1 = done.encode().unwrap();
        assert_eq!(v1[4], VERSION);
        assert_eq!(v1.len() + 64, bytes.len());
        // A version 2 header without the pending section is truncated, and vice versa.
        let mut short = v1.to_vec();
        short[4] = VERSION_PENDING_PIN;
        assert_eq!(GateStore::decode(&short), Err(DecodeError::Truncated));
        let mut long = bytes.to_vec();
        long[4] = VERSION;
        assert_eq!(GateStore::decode(&long), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn version_1_files_still_decode() {
        // Layout written by releases before the pending-PIN field existed.
        let mut v1 = Vec::new();
        v1.extend_from_slice(b"PKTG");
        v1.push(1);
        v1.extend_from_slice(&0x0150_0001_u32.to_be_bytes());
        v1.extend_from_slice(&[9; 32]);
        v1.push(1);
        v1.extend_from_slice(&0x0150_0002_u32.to_be_bytes());
        v1.extend_from_slice(&[3; 32]);
        v1.extend_from_slice(&0x0150_0003_u32.to_be_bytes());
        v1.extend_from_slice(&[4; 32]);
        v1.extend_from_slice(&[0x77; 32]);
        v1.extend_from_slice(&[0, 5, 0, 0x0b, 7, 7, 7]);
        let store = GateStore::decode(&v1).unwrap();
        assert_eq!(
            store,
            GateStore {
                pin_bootstrap: None,
                ..sample()
            }
        );
        assert_eq!(store.encode().unwrap().as_slice(), v1.as_slice());
    }

    #[test]
    fn corrupt_files_are_errors() {
        let good = sample().encode().unwrap();
        let mut magic = good.to_vec();
        magic[0] = b'X';
        assert_eq!(GateStore::decode(&magic), Err(DecodeError::BadMagic));
        let mut version = good.to_vec();
        version[4] = 9;
        assert_eq!(
            GateStore::decode(&version),
            Err(DecodeError::UnknownVersion)
        );
        let mut state = good.to_vec();
        state[4 + 1 + 4 + 32] = 2;
        assert_eq!(GateStore::decode(&state), Err(DecodeError::InvalidPinState));
        assert_eq!(
            GateStore::decode(&good[..good.len() - 1]),
            Err(DecodeError::Truncated)
        );
        let mut trailing = good.to_vec();
        trailing.push(1);
        assert_eq!(
            GateStore::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        assert_eq!(GateStore::decode(&[]), Err(DecodeError::Truncated));
    }

    #[test]
    fn debug_redacts_secrets() {
        let text = format!("{:?}", sample());
        assert!(text.contains("<redacted>"));
        assert!(!text.contains("[3, 3, 3"));
        let pending = GateStore {
            pending_pin: Some(PendingPin {
                salt: [5; 32],
                auth: secret(6),
            }),
            ..sample()
        };
        assert!(!format!("{pending:?}").contains("[6, 6, 6"));
    }

    proptest! {
        #[test]
        fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
            let _ = GateStore::decode(&bytes);
        }

        #[test]
        fn encode_decode_round_trip(
            bootstrap in prop::option::of(any::<[u8; 32]>()),
            pending in prop::option::of((any::<[u8; 32]>(), any::<[u8; 32]>())),
            srk_name in prop::collection::vec(any::<u8>(), 1..100),
        ) {
            let store = GateStore {
                pin_bootstrap: bootstrap.map(|b| AuthValue(Zeroizing::new(b))),
                srk_name,
                pending_pin: pending.map(|(salt, auth)| PendingPin {
                    salt,
                    auth: AuthValue(Zeroizing::new(auth)),
                }),
                ..sample()
            };
            let bytes = store.encode().unwrap();
            prop_assert_eq!(GateStore::decode(&bytes), Ok(store));
        }
    }
}

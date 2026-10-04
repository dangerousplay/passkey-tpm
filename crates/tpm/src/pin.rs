//! clientPIN storage in the TPM (TPM-08, TPM-09).
//!
//! CTAP authenticators store `LEFT(SHA-256(PIN), 16)` ("pinHash", CTAP 2.1 §6.5.5.5) and
//! only ever receive that value afterwards. We stretch it with Argon2id and use the result
//! as the PIN gate's authValue, so the PIN itself is checked by the TPM, with
//! dictionary-attack protection, and is never stored.

use argon2::{Algorithm, Argon2, Params, Version};
use passkey_tpm_wire::gatestore::{AuthValue, GateStore, PendingPin};
use tss_esapi::Context;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::gates::random32;
use crate::nvgate::{self, Lockout};
use crate::srk::Srk;

/// Argon2id cost: 19 MiB, 2 passes, 1 lane (OWASP minimum recommendation for Argon2id).
/// The TPM's DA lockout is the main defence against guessing; this slows offline attacks
/// on a stolen gate file, whose PIN gate authValue the attacker would still need the TPM to use.
pub const ARGON2_M_KIB: u32 = 19 * 1024;
pub const ARGON2_T: u32 = 2;
pub const ARGON2_P: u32 = 1;

/// Derives the PIN gate authValue from `pinHash` (16 bytes) and the user's salt.
///
/// # Errors
/// [`Error::Corrupt`] if Argon2 fails (parameters are constant, so only on allocation failure).
pub fn derive_auth(pin_hash: &[u8; 16], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|_| Error::Corrupt("Argon2 parameters"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin_hash, salt, out.as_mut_slice())
        .map_err(|_| Error::Corrupt("Argon2 derivation"))?;
    Ok(out)
}

/// Sets the first PIN: [`begin_set`] then [`complete`]. Returns the updated store, which the
/// caller must persist. The broker persists the [`begin_set`] result first instead (HARD-06).
///
/// # Errors
/// As [`begin_set`] and [`complete`].
pub fn set_pin(
    ctx: &mut Context,
    srk: &Srk,
    store: &GateStore,
    new_pin_hash: &[u8; 16],
) -> Result<GateStore> {
    let pending = begin_set(ctx, srk, store, new_pin_hash)?;
    complete(ctx, srk, &pending)
}

/// Changes the PIN: [`begin_change`] then [`complete`].
///
/// # Errors
/// As [`begin_change`] and [`complete`].
pub fn change_pin(
    ctx: &mut Context,
    srk: &Srk,
    store: &GateStore,
    old_pin_hash: &[u8; 16],
    new_pin_hash: &[u8; 16],
) -> Result<GateStore> {
    let pending = begin_change(ctx, srk, store, old_pin_hash, new_pin_hash)?;
    complete(ctx, srk, &pending)
}

/// First step of setting the first PIN: checks the bootstrap secret and returns the store
/// with the new PIN as a pending change. Nothing on the TPM changes. The caller persists the
/// result, then calls [`complete`].
///
/// # Errors
/// [`Error::Corrupt`] if a PIN is already set or a change is pending; TPM errors otherwise.
pub fn begin_set(
    ctx: &mut Context,
    srk: &Srk,
    store: &GateStore,
    new_pin_hash: &[u8; 16],
) -> Result<GateStore> {
    let bootstrap = store
        .pin_bootstrap
        .as_ref()
        .ok_or(Error::Corrupt("PIN already set"))?;
    begin(ctx, srk, store, &bootstrap.0, new_pin_hash)
}

/// First step of a PIN change: the TPM verifies the old PIN (a wrong one counts towards
/// dictionary-attack lockout and changes nothing); returns the store with the new PIN as a
/// pending change. The caller persists the result, then calls [`complete`].
///
/// # Errors
/// [`Error::Corrupt`] if no PIN is set or a change is pending; TPM errors (including
/// authorisation failure).
pub fn begin_change(
    ctx: &mut Context,
    srk: &Srk,
    store: &GateStore,
    old_pin_hash: &[u8; 16],
    new_pin_hash: &[u8; 16],
) -> Result<GateStore> {
    if store.pin_bootstrap.is_some() {
        return Err(Error::Corrupt("no PIN set"));
    }
    let old_auth = derive_auth(old_pin_hash, &store.pin_salt)?;
    begin(ctx, srk, store, &old_auth, new_pin_hash)
}

fn begin(
    ctx: &mut Context,
    srk: &Srk,
    store: &GateStore,
    old_auth: &[u8; 32],
    new_pin_hash: &[u8; 16],
) -> Result<GateStore> {
    if store.pending_pin.is_some() {
        return Err(Error::Corrupt("PIN change already pending"));
    }
    nvgate::check(ctx, srk, store.pin_nv_index, old_auth)?;
    let salt = *random32()?;
    let auth = derive_auth(new_pin_hash, &salt)?;
    Ok(GateStore {
        pending_pin: Some(PendingPin {
            salt,
            auth: AuthValue(auth),
        }),
        ..store.clone()
    })
}

/// Completes a pending PIN change: (re)defines the PIN NV index with the new secret and
/// returns the store without the pending change, which the caller must persist. Idempotent,
/// so it also repairs a change interrupted at any step (HARD-06, AD-011): the new PIN is
/// then in force. A store without a pending change is returned unchanged.
///
/// # Errors
/// [`Error::Corrupt`] if another index occupies the PIN gate's; TPM errors otherwise.
pub fn complete(ctx: &mut Context, srk: &Srk, store: &GateStore) -> Result<GateStore> {
    let Some(pending) = &store.pending_pin else {
        return Ok(store.clone());
    };
    nvgate::redefine(
        ctx,
        srk,
        store.pin_nv_index,
        Lockout::Protected,
        &pending.auth.0,
    )?;
    Ok(GateStore {
        pin_salt: pending.salt,
        pin_bootstrap: None,
        pending_pin: None,
        ..store.clone()
    })
}

/// Verifies `pin_hash` against the PIN gate. The TPM performs the comparison, and a wrong
/// PIN counts towards dictionary-attack lockout. After success the caller may use the UV
/// gate ([`crate::policy::KeyGate::from`] maps PIN to UV).
///
/// # Errors
/// [`Error::Corrupt`] if no PIN is set; TPM authorisation errors for a wrong PIN.
pub fn verify(ctx: &mut Context, srk: &Srk, store: &GateStore, pin_hash: &[u8; 16]) -> Result<()> {
    if store.pin_bootstrap.is_some() {
        return Err(Error::Corrupt("no PIN set"));
    }
    let auth = derive_auth(pin_hash, &store.pin_salt)?;
    nvgate::check(ctx, srk, store.pin_nv_index, &auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_salted() {
        let a = derive_auth(&[1; 16], &[2; 32]).unwrap();
        assert_eq!(*a, *derive_auth(&[1; 16], &[2; 32]).unwrap());
        assert_ne!(*a, *derive_auth(&[1; 16], &[3; 32]).unwrap());
        assert_ne!(*a, *derive_auth(&[9; 16], &[2; 32]).unwrap());
    }

    #[test]
    fn parameters_are_pinned() {
        // Changing the KDF would lock every user out of their PIN; this regression vector
        // makes that an explicit, reviewed change. Cross-checked with the reference C
        // implementation: `argon2 <salt> -id -t 2 -k 19456 -p 1 -l 32 -r`.
        let out = derive_auth(&[0x11; 16], &[0x22; 32]).unwrap();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, include_str!("pin_kdf_vector.txt").trim());
    }
}

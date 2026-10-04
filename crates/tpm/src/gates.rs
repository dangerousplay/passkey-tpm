//! Per-user gate provisioning (ADR 0003, AD-013, TPM-04/05/08).
//!
//! Each user gets three NV-index gates whose secrets only the broker holds:
//! - PIN: dictionary-attack protected, secret derived from the PIN ([`crate::pin`]);
//! - UV and UP: random 32-byte secrets, `noDA`. Credential keys name these in their policy.

use passkey_tpm_wire::gatestore::{AuthValue, Gate, GateStore};
use tss_esapi::Context;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::nvgate::{self, Lockout};
use crate::policy::{GateNames, KeyGate};
use crate::srk::Srk;

/// Fresh 32 random bytes from the OS.
///
/// # Errors
/// [`Error::Corrupt`] if the OS RNG fails.
pub fn random32() -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    getrandom::fill(out.as_mut_slice())
        .map_err(|_| Error::Corrupt("OS random number generator"))?;
    Ok(out)
}

/// NV indexes for one user's gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateIndexes {
    pub pin: u32,
    pub uv: u32,
    pub up: u32,
}

fn define_gate(ctx: &mut Context, srk: &Srk, index: u32) -> Result<Gate> {
    let auth = random32()?;
    nvgate::define(ctx, srk, index, Lockout::Exempt, &auth)?;
    Ok(Gate {
        nv_index: index,
        auth: AuthValue(auth),
    })
}

/// Creates a user's gates. The PIN gate gets a random bootstrap secret (no PIN set yet).
/// If a step fails, the gates this call defined are undefined again (HARD-09).
///
/// # Errors
/// TPM errors, e.g. if an index is taken or the Owner hierarchy needs a password.
pub fn provision(ctx: &mut Context, srk: &Srk, indexes: GateIndexes) -> Result<GateStore> {
    let mut created = Vec::new();
    let result = define_all(ctx, srk, indexes, &mut created);
    if result.is_err() {
        undefine_all(ctx, &created);
    }
    result
}

fn define_all(
    ctx: &mut Context,
    srk: &Srk,
    indexes: GateIndexes,
    created: &mut Vec<u32>,
) -> Result<GateStore> {
    let bootstrap = random32()?;
    nvgate::define(ctx, srk, indexes.pin, Lockout::Protected, &bootstrap)?;
    created.push(indexes.pin);
    let uv = define_gate(ctx, srk, indexes.uv)?;
    created.push(indexes.uv);
    let up = define_gate(ctx, srk, indexes.up)?;
    created.push(indexes.up);
    Ok(GateStore {
        pin_nv_index: indexes.pin,
        pin_salt: *random32()?,
        pin_bootstrap: Some(AuthValue(bootstrap)),
        uv,
        up,
        cred_mac_key: AuthValue(random32()?),
        srk_name: srk.name.clone(),
    })
}

/// The Names of a user's key gates, as referenced by credential policies.
///
/// # Errors
/// TPM errors reading the NV indexes, or [`Error::Corrupt`] if one was replaced.
pub fn names(ctx: &mut Context, store: &GateStore) -> Result<GateNames> {
    Ok(GateNames {
        uv: nvgate::name(ctx, store.uv.nv_index, Lockout::Exempt)?,
        up: nvgate::name(ctx, store.up.nv_index, Lockout::Exempt)?,
    })
}

/// The stored gate for a key gate.
#[must_use]
pub fn gate(store: &GateStore, gate: KeyGate) -> &Gate {
    match gate {
        KeyGate::Uv => &store.uv,
        KeyGate::Up => &store.up,
    }
}

/// Removes all of a user's gates (account removal, tests).
///
/// # Errors
/// TPM errors.
pub fn remove(ctx: &mut Context, store: &GateStore) -> Result<()> {
    for index in [store.pin_nv_index, store.uv.nv_index, store.up.nv_index] {
        nvgate::undefine(ctx, index)?;
    }
    Ok(())
}

/// Best-effort removal of gates that were just provisioned but could not be persisted.
pub fn discard(ctx: &mut Context, store: &GateStore) {
    undefine_all(
        ctx,
        &[store.pin_nv_index, store.uv.nv_index, store.up.nv_index],
    );
}

/// Undefines `indexes`, ignoring errors: cleanup after an earlier failure.
fn undefine_all(ctx: &mut Context, indexes: &[u32]) {
    for &index in indexes {
        let _ = nvgate::undefine(ctx, index);
    }
}

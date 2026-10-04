//! Gated use of credential keys: signing and hmac-secret (TPM-02/03/05/06/07/12, AD-013).
//!
//! The TPM releases a signature only inside a policy session that satisfied
//! `PolicySecret(gate, policyRef(gate, rpIdHash))` for one of the key's branches.
//!
//! Command order matters on real hardware: the kernel resource manager reloads every live
//! context of our connection before each command, so the policy is built *before* the key
//! is loaded, keeping at most one context alive for most of the sequence.

use passkey_tpm_core::gates::{hmac_uses_with_uv_key, sign_allowed};
use passkey_tpm_core::tpm_iface::{CredBlobs, GateKind, RpIdHash};
use passkey_tpm_wire::credid::KeyBlobs;
use passkey_tpm_wire::gatestore::GateStore;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{Digest, DigestList, MaxBuffer, Signature, SignatureScheme};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::Context;

use crate::credential::pad32;
use crate::error::{Error, Result};
use crate::policy::{self, GateNames, KeyGate, Purpose};
use crate::srk::Srk;
use crate::{gates, nvgate, objects, session};

/// One user's gate material.
#[derive(Debug)]
pub struct UserGates<'a> {
    pub store: &'a GateStore,
    pub names: &'a GateNames,
}

/// Satisfies the key's policy through `gate` in `policy`.
fn authorise(
    ctx: &mut Context,
    srk: &Srk,
    policy: PolicySession,
    user: &UserGates<'_>,
    rp: &RpIdHash,
    gate: KeyGate,
    branch_gates: &[KeyGate],
) -> Result<()> {
    let g = gates::gate(user.store, gate);
    nvgate::satisfy(
        ctx,
        srk,
        policy,
        g.nv_index,
        &g.auth.0,
        &policy::policy_ref(gate, rp),
    )?;
    if branch_gates.len() > 1 {
        let mut list = DigestList::new();
        for d in policy::branches(user.names, rp, branch_gates) {
            list.add(Digest::try_from(d.to_vec())?)?;
        }
        ctx.policy_or(policy, list)?;
    }
    Ok(())
}

/// Builds the policy, then loads `key_blobs` and runs `op` authorised by the session.
#[allow(clippy::too_many_arguments)]
fn gated<T>(
    ctx: &mut Context,
    srk: &Srk,
    user: &UserGates<'_>,
    rp: &RpIdHash,
    gate: KeyGate,
    branch_gates: &[KeyGate],
    key_blobs: &KeyBlobs,
    secret_response: bool,
    op: impl FnOnce(&mut Context, AuthSession, KeyHandle) -> Result<T>,
) -> Result<T> {
    session::with_policy(ctx, srk, secret_response, |ctx, session, policy| {
        authorise(ctx, srk, policy, user, rp, gate, branch_gates)?;
        let key = objects::load(ctx, srk, key_blobs, None)?;
        let result = op(ctx, session, key);
        objects::flush(ctx, key);
        result
    })
}

fn null_ticket() -> Result<tss_esapi::structures::HashcheckTicket> {
    let raw = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    Ok(raw.try_into()?)
}

/// Signs `digest` with the credential key through `gate`, claiming the key has the
/// branches `branch_gates`. Prefer [`sign`]; this form lets tests show that the TPM itself
/// enforces the policy even when the caller lies about the branches.
///
/// # Errors
/// TPM errors, including policy failures for the wrong user, RP or gate.
#[allow(clippy::too_many_arguments)]
pub fn sign_with_branches(
    ctx: &mut Context,
    srk: &Srk,
    user: &UserGates<'_>,
    blobs: &CredBlobs,
    rp: &RpIdHash,
    gate: KeyGate,
    branch_gates: &[KeyGate],
    digest: &[u8; 32],
) -> Result<Vec<u8>> {
    let message = Digest::try_from(digest.to_vec())?;
    let ticket = null_ticket()?;
    gated(
        ctx,
        srk,
        user,
        rp,
        gate,
        branch_gates,
        &blobs.key,
        false,
        |ctx, session, key| {
            let signature = ctx.execute_with_session(Some(session), |ctx| {
                ctx.sign(key, message, SignatureScheme::Null, ticket)
            })?;
            to_der(&signature)
        },
    )
}

/// Signs `digest` with the credential through the gate `kind` unlocks (ADR 0003, AD-013).
/// A PIN must have been verified ([`crate::pin::verify`]) before passing [`GateKind::Pin`].
///
/// # Errors
/// [`Error::Corrupt`] if `kind` isn't permitted for the credential; TPM errors otherwise.
pub fn sign(
    ctx: &mut Context,
    srk: &Srk,
    user: &UserGates<'_>,
    blobs: &CredBlobs,
    rp: &RpIdHash,
    kind: GateKind,
    digest: &[u8; 32],
) -> Result<Vec<u8>> {
    if !sign_allowed(blobs.protect, kind) {
        return Err(Error::Corrupt("gate not permitted for this credential"));
    }
    let branch_gates = policy::gates_for(blobs.protect, Purpose::Sign);
    sign_with_branches(
        ctx,
        srk,
        user,
        blobs,
        rp,
        KeyGate::from(kind),
        branch_gates,
        digest,
    )
}

/// hmac-secret: HMAC-SHA-256(CredRandom, salt) with CredRandomWithUV for UV/PIN and
/// CredRandomWithoutUV for presence (CTAP 2.1 §12.5). The output is encrypted on a
/// discrete TPM's bus.
///
/// # Errors
/// [`Error::Corrupt`] if the credential has no hmac-secret keys or `kind` isn't permitted;
/// TPM errors otherwise.
pub fn hmac(
    ctx: &mut Context,
    srk: &Srk,
    user: &UserGates<'_>,
    blobs: &CredBlobs,
    rp: &RpIdHash,
    kind: GateKind,
    salt: &[u8; 32],
) -> Result<[u8; 32]> {
    if !sign_allowed(blobs.protect, kind) {
        return Err(Error::Corrupt("gate not permitted for this credential"));
    }
    let keys = blobs
        .hmac
        .as_ref()
        .ok_or(Error::Corrupt("credential has no hmac-secret keys"))?;
    let with_uv = hmac_uses_with_uv_key(kind);
    let (key_blobs, purpose) = if with_uv {
        (&keys.with_uv, Purpose::HmacWithUv)
    } else {
        (&keys.without_uv, Purpose::HmacWithoutUv)
    };
    let branch_gates = policy::gates_for(blobs.protect, purpose);
    let buffer = MaxBuffer::try_from(salt.to_vec())?;
    gated(
        ctx,
        srk,
        user,
        rp,
        KeyGate::from(kind),
        branch_gates,
        key_blobs,
        true,
        |ctx, session, key| {
            let out = ctx.execute_with_session(Some(session), |ctx| {
                ctx.hmac(ObjectHandle::from(key), buffer, HashingAlgorithm::Sha256)
            })?;
            pad32(out.value())
        },
    )
}

fn to_der(signature: &Signature) -> Result<Vec<u8>> {
    let Signature::EcDsa(ecc) = signature else {
        return Err(Error::Corrupt("TPM returned a non-ECDSA signature"));
    };
    let r = pad32(ecc.signature_r().value())?;
    let s = pad32(ecc.signature_s().value())?;
    let sig =
        p256::ecdsa::Signature::from_scalars(r, s).map_err(|_| Error::Corrupt("ECDSA scalars"))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

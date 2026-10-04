//! Policy-bound credential creation (TPM-01/02/07/12/16).

use passkey_tpm_core::tpm_iface::{CredBlobs, CredProtect, RpIdHash};
use passkey_tpm_wire::credid::HmacBlobs;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, KeyedHashScheme, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters,
};
use tss_esapi::Context;

use crate::error::{Error, Result};
use crate::objects;
use crate::policy::{self, GateNames, Purpose};
use crate::srk::Srk;

fn digest(d: policy::Digest) -> Result<Digest> {
    Ok(Digest::try_from(d.to_vec())?)
}

/// ECDSA P-256 / SHA-256 signing key usable only through its policy.
fn credential_template(auth_policy: policy::Digest) -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_sign_encrypt(true)
        .build()?;
    let params = PublicEccParametersBuilder::new_unrestricted_signing_key(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(digest(auth_policy)?)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

/// HMAC-SHA-256 key whose 32-byte secret the TPM generates (CTAP CredRandom).
fn hmac_template(auth_policy: policy::Digest) -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_sign_encrypt(true)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(digest(auth_policy)?)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()?)
}

fn create_object(
    ctx: &mut Context,
    srk: &Srk,
    template: Public,
) -> Result<passkey_tpm_wire::credid::KeyBlobs> {
    // No secret travels in TPM2_Create: the TPM generates the key and no authValue is set.
    let created = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create(srk.handle, template, None, None, None, None)
    })?;
    objects::to_blobs(&created.out_public, &created.out_private)
}

/// Creates a credential for `rp` bound to the gates named in `names`.
///
/// # Errors
/// TPM errors; [`Error::Corrupt`] if the policy can't be built.
pub fn create(
    ctx: &mut Context,
    srk: &Srk,
    names: &GateNames,
    rp: &RpIdHash,
    protect: CredProtect,
    with_hmac: bool,
) -> Result<CredBlobs> {
    let sign_gates = policy::gates_for(protect, Purpose::Sign);
    let sign_policy = policy::key_policy(names, rp, sign_gates)
        .map_err(|_| Error::Corrupt("credential policy"))?;
    let key = create_object(ctx, srk, credential_template(sign_policy)?)?;

    let hmac = if with_hmac {
        let mut keys = Vec::with_capacity(2);
        for purpose in [Purpose::HmacWithUv, Purpose::HmacWithoutUv] {
            let gates = policy::gates_for(protect, purpose);
            let p = policy::key_policy(names, rp, gates)
                .map_err(|_| Error::Corrupt("hmac-secret policy"))?;
            keys.push(create_object(ctx, srk, hmac_template(p)?)?);
        }
        let without_uv = keys.pop().ok_or(Error::Corrupt("hmac keys"))?;
        let with_uv = keys.pop().ok_or(Error::Corrupt("hmac keys"))?;
        Some(HmacBlobs {
            with_uv,
            without_uv,
        })
    } else {
        None
    };
    Ok(CredBlobs { protect, key, hmac })
}

/// The credential's public key as uncompressed P-256 coordinates.
///
/// # Errors
/// [`Error::Corrupt`] if the blob is not a P-256 public area.
pub fn public_point(blobs: &CredBlobs) -> Result<([u8; 32], [u8; 32])> {
    let (public, _) = objects::from_blobs(&blobs.key)?;
    match public {
        Public::Ecc { unique, .. } => {
            let x = pad32(unique.x().value())?;
            let y = pad32(unique.y().value())?;
            Ok((x, y))
        }
        _ => Err(Error::Corrupt("credential key is not ECC")),
    }
}

pub(crate) fn pad32(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let start = 32usize
        .checked_sub(bytes.len())
        .ok_or(Error::Corrupt("coordinate longer than 32 bytes"))?;
    out.get_mut(start..)
        .ok_or(Error::Corrupt("coordinate"))?
        .copy_from_slice(bytes);
    Ok(out)
}

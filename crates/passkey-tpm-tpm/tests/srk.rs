mod support;

use passkey_tpm_tpm::{srk, Error};
use support::swtpm::Swtpm;
use tss_esapi::handles::{ObjectHandle, PersistentTpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::structures::{EccScheme, HashScheme};
use tss_esapi::utils::create_unrestricted_signing_ecc_public;

#[test]
fn provisions_once_and_reuses() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    assert!(matches!(srk::open(&mut ctx), Err(Error::SrkMissing)));
    let first = srk::ensure(&mut ctx).expect("provision SRK");
    let second = srk::ensure(&mut ctx).expect("reuse SRK");
    assert_eq!(first.name, second.name);
    assert_eq!(first.name.len(), 34, "nameAlg (2) + SHA-256 (32)");
    srk::open_pinned(&mut ctx, &first.name).expect("pinned name matches");
}

#[test]
fn detects_name_change() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("provision SRK");
    let mut other = srk.name.clone();
    other[5] ^= 1;
    assert!(matches!(
        srk::open_pinned(&mut ctx, &other),
        Err(Error::SrkMismatch)
    ));
}

#[test]
fn refuses_foreign_object_at_srk_handle() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    // An attacker-controlled signing key squatting on 0x81000001.
    let public = create_unrestricted_signing_ecc_public(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .expect("template");
    let key = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .expect("create foreign key");
    let handle = PersistentTpmHandle::new(srk::SRK_HANDLE).expect("handle");
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.evict_control(
            Provision::Owner,
            ObjectHandle::from(key.key_handle),
            Persistent::Persistent(handle),
        )
    })
    .expect("persist foreign key");
    assert!(matches!(srk::ensure(&mut ctx), Err(Error::NotAnSrk)));
}

/// Mirrors machines where Windows or systemd already created the TCG RSA-2048 SRK.
#[test]
fn reuses_an_existing_rsa_srk_for_the_whole_flow() {
    use passkey_tpm_core::tpm_iface::{CredProtect, GateKind, RpIdHash};
    use passkey_tpm_tpm::gates::GateIndexes;
    use passkey_tpm_tpm::sign::{self, UserGates};
    use passkey_tpm_tpm::{credential, gates, nvgate};
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::algorithm::PublicAlgorithm;
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::structures::{
        PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
        SymmetricDefinitionObject,
    };

    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .expect("attributes");
    let params = PublicRsaParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::ZERO_EXPONENT,
    )
    .build()
    .expect("params");
    let rsa_srk = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_parameters(params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("RSA SRK template");
    let key = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, rsa_srk, None, None, None, None)
        })
        .expect("create RSA SRK");
    let handle = PersistentTpmHandle::new(srk::SRK_HANDLE).expect("handle");
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.evict_control(
            Provision::Owner,
            ObjectHandle::from(key.key_handle),
            Persistent::Persistent(handle),
        )
    })
    .expect("persist RSA SRK");
    ctx.flush_context(ObjectHandle::from(key.key_handle))
        .expect("flush transient copy");

    let srk = srk::ensure(&mut ctx).expect("existing RSA SRK accepted");
    let store = gates::provision(
        &mut ctx,
        &srk,
        GateIndexes {
            pin: nvgate::NV_BASE + 9,
            uv: nvgate::NV_BASE + 10,
            up: nvgate::NV_BASE + 11,
        },
    )
    .expect("gates under RSA SRK");
    let names = gates::names(&mut ctx, &store).expect("names");
    let rp = RpIdHash([3; 32]);
    let blobs = credential::create(&mut ctx, &srk, &names, &rp, CredProtect::UvRequired, true)
        .expect("create");
    let user = UserGates {
        store: &store,
        names: &names,
    };
    sign::sign(&mut ctx, &srk, &user, &blobs, &rp, GateKind::Uv, &[1; 32])
        .expect("sign (RSA-salted session)");
    sign::hmac(&mut ctx, &srk, &user, &blobs, &rp, GateKind::Uv, &[2; 32]).expect("hmac-secret");
}

//! Credential creation, gated signing and hmac-secret against swtpm, including the bypass
//! attempts each TPM requirement rules out.

mod support;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use passkey_tpm_core::tpm_iface::{CredBlobs, CredProtect, GateKind, RpIdHash};
use passkey_tpm_tpm::gates::GateIndexes;
use passkey_tpm_tpm::policy::{self, GateNames, KeyGate, Purpose};
use passkey_tpm_tpm::sign::{self, UserGates};
use passkey_tpm_tpm::srk::Srk;
use passkey_tpm_tpm::{credential, gates, nvgate, objects, srk};
use passkey_tpm_wire::gatestore::GateStore;
use support::swtpm::Swtpm;
use tss_esapi::Context;

const RP: RpIdHash = RpIdHash([0x11; 32]);
const OTHER_RP: RpIdHash = RpIdHash([0x22; 32]);
const DIGEST: [u8; 32] = [0x42; 32];

struct Fixture {
    _tpm: Swtpm,
    ctx: Context,
    srk: Srk,
    a: GateStore,
    a_names: GateNames,
    b: GateStore,
    b_names: GateNames,
}

fn fixture() -> Fixture {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let a = gates::provision(
        &mut ctx,
        &srk,
        GateIndexes {
            pin: nvgate::NV_BASE + 1,
            uv: nvgate::NV_BASE + 2,
            up: nvgate::NV_BASE + 3,
        },
    )
    .expect("user A");
    let b = gates::provision(
        &mut ctx,
        &srk,
        GateIndexes {
            pin: nvgate::NV_BASE + 4,
            uv: nvgate::NV_BASE + 5,
            up: nvgate::NV_BASE + 6,
        },
    )
    .expect("user B");
    let a_names = gates::names(&mut ctx, &a).expect("names A");
    let b_names = gates::names(&mut ctx, &b).expect("names B");
    Fixture {
        _tpm: tpm,
        ctx,
        srk,
        a,
        a_names,
        b,
        b_names,
    }
}

fn user<'a>(store: &'a GateStore, names: &'a GateNames) -> UserGates<'a> {
    UserGates { store, names }
}

/// The bypass must be stopped by the TPM's policy check, not by some unrelated error.
fn assert_policy_failure<T: std::fmt::Debug>(result: passkey_tpm_tpm::Result<T>, what: &str) {
    match result {
        Err(passkey_tpm_tpm::Error::Tss(e)) => {
            assert!(
                e.to_string().contains("policy check failed"),
                "{what}: unexpected TPM error {e}"
            );
        }
        other => panic!("{what}: expected a TPM policy failure, got {other:?}"),
    }
}

fn verify(blobs: &CredBlobs, der: &[u8]) {
    let (x, y) = credential::public_point(blobs).expect("point");
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let key = VerifyingKey::from_sec1_bytes(&sec1).expect("public key");
    let sig = Signature::from_der(der).expect("DER");
    key.verify_prehash(&DIGEST, &sig)
        .expect("signature verifies");
}

#[test]
fn key_policy_matches_software_and_user_auth_is_off() {
    let mut f = fixture();
    let blobs = credential::create(
        &mut f.ctx,
        &f.srk,
        &f.a_names,
        &RP,
        CredProtect::UvOptional,
        true,
    )
    .expect("create");
    let handle = objects::load(&mut f.ctx, &f.srk, &blobs.key, None).expect("load");
    let (public, _, _) = f.ctx.read_public(handle).expect("read_public");
    objects::flush(&mut f.ctx, handle);
    let gates = policy::gates_for(CredProtect::UvOptional, Purpose::Sign);
    let expected = policy::key_policy(&f.a_names, &RP, gates).expect("policy");
    assert_eq!(public.auth_policy().value(), expected.as_slice());
    assert!(
        !public.object_attributes().user_with_auth(),
        "TPM-02: no password use"
    );

    let id = blobs.encode().expect("encode");
    eprintln!("credential ID with hmac-secret keys: {} bytes", id.len());
    assert!(id.len() <= passkey_tpm_wire::credid::MAX_LEN, "TPM-16");
}

#[test]
fn every_permitted_gate_produces_a_valid_signature() {
    let mut f = fixture();
    let blobs = credential::create(
        &mut f.ctx,
        &f.srk,
        &f.a_names,
        &RP,
        CredProtect::UvOptional,
        false,
    )
    .expect("create");
    let a = user(&f.a, &f.a_names);
    for gate in [GateKind::Pin, GateKind::Uv, GateKind::Up] {
        let der = sign::sign(&mut f.ctx, &f.srk, &a, &blobs, &RP, gate, &DIGEST).expect("sign");
        verify(&blobs, &der);
    }
}

#[test]
fn tpm_03_plain_password_use_is_refused() {
    let mut f = fixture();
    let blobs = credential::create(
        &mut f.ctx,
        &f.srk,
        &f.a_names,
        &RP,
        CredProtect::UvOptional,
        false,
    )
    .expect("create");
    let key = objects::load(&mut f.ctx, &f.srk, &blobs.key, None).expect("load");
    let ticket = {
        use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
        tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        }
        .try_into()
        .expect("ticket")
    };
    let result = f.ctx.execute_with_nullauth_session(|ctx| {
        ctx.sign(
            key,
            tss_esapi::structures::Digest::try_from(DIGEST.to_vec()).expect("digest"),
            tss_esapi::structures::SignatureScheme::Null,
            ticket,
        )
    });
    // TPM_RC_AUTH_UNAVAILABLE: userWithAuth is clear, so a password session can't authorise.
    let err = result.expect_err("any tss group member could sign otherwise");
    assert!(
        err.to_string()
            .contains("authValue or authPolicy is not available"),
        "unexpected TPM error {err}"
    );
}

#[test]
fn tpm_05_other_users_gate_is_refused() {
    let mut f = fixture();
    let blobs = credential::create(
        &mut f.ctx,
        &f.srk,
        &f.a_names,
        &RP,
        CredProtect::UvOptional,
        false,
    )
    .expect("create");
    let b = user(&f.b, &f.b_names);
    for gate in [GateKind::Uv, GateKind::Up, GateKind::Pin] {
        assert_policy_failure(
            sign::sign(&mut f.ctx, &f.srk, &b, &blobs, &RP, gate, &DIGEST),
            &format!("user B with user A's credential via {gate:?}"),
        );
    }
}

#[test]
fn tpm_06_other_relying_party_is_refused() {
    let mut f = fixture();
    let blobs = credential::create(
        &mut f.ctx,
        &f.srk,
        &f.a_names,
        &RP,
        CredProtect::UvOptional,
        false,
    )
    .expect("create");
    let a = user(&f.a, &f.a_names);
    assert_policy_failure(
        sign::sign(
            &mut f.ctx,
            &f.srk,
            &a,
            &blobs,
            &OTHER_RP,
            GateKind::Uv,
            &DIGEST,
        ),
        "credential used for another RP",
    );
}

#[test]
fn tpm_12_presence_cannot_use_uv_required_credentials_even_at_the_tpm() {
    let mut f = fixture();
    let blobs = credential::create(
        &mut f.ctx,
        &f.srk,
        &f.a_names,
        &RP,
        CredProtect::UvRequired,
        false,
    )
    .expect("create");
    let a = user(&f.a, &f.a_names);
    // The high-level API refuses up front …
    assert!(sign::sign(&mut f.ctx, &f.srk, &a, &blobs, &RP, GateKind::Up, &DIGEST).is_err());
    // … and so does the TPM, even if the caller claims the presence branch exists.
    let claimed = [KeyGate::Uv, KeyGate::Up];
    assert_policy_failure(
        sign::sign_with_branches(
            &mut f.ctx,
            &f.srk,
            &a,
            &blobs,
            &RP,
            KeyGate::Up,
            &claimed,
            &DIGEST,
        ),
        "presence branch on a credProtect=3 credential",
    );
    // UV still works.
    let der =
        sign::sign(&mut f.ctx, &f.srk, &a, &blobs, &RP, GateKind::Uv, &DIGEST).expect("UV sign");
    verify(&blobs, &der);
}

#[test]
fn hmac_secret_is_deterministic_and_separated_by_uv() {
    let mut f = fixture();
    let blobs = credential::create(
        &mut f.ctx,
        &f.srk,
        &f.a_names,
        &RP,
        CredProtect::UvOptional,
        true,
    )
    .expect("create");
    let a = user(&f.a, &f.a_names);
    let salt1 = [1u8; 32];
    let salt2 = [2u8; 32];
    let uv1 = sign::hmac(&mut f.ctx, &f.srk, &a, &blobs, &RP, GateKind::Uv, &salt1).expect("uv");
    let uv1_again =
        sign::hmac(&mut f.ctx, &f.srk, &a, &blobs, &RP, GateKind::Uv, &salt1).expect("uv again");
    let pin1 = sign::hmac(&mut f.ctx, &f.srk, &a, &blobs, &RP, GateKind::Pin, &salt1).expect("pin");
    let up1 = sign::hmac(&mut f.ctx, &f.srk, &a, &blobs, &RP, GateKind::Up, &salt1).expect("up");
    let uv2 =
        sign::hmac(&mut f.ctx, &f.srk, &a, &blobs, &RP, GateKind::Uv, &salt2).expect("uv salt2");
    assert_eq!(uv1, uv1_again, "deterministic per credential and salt");
    assert_eq!(
        uv1, pin1,
        "PIN and fingerprint both select CredRandomWithUV"
    );
    assert_ne!(uv1, up1, "CredRandomWithoutUV differs");
    assert_ne!(uv1, uv2, "salt changes the output");

    // The hmac-secret keys are bound to the user and RP like the signing key.
    let b = user(&f.b, &f.b_names);
    assert_policy_failure(
        sign::hmac(&mut f.ctx, &f.srk, &b, &blobs, &RP, GateKind::Uv, &salt1),
        "hmac-secret by another user",
    );
    assert_policy_failure(
        sign::hmac(
            &mut f.ctx,
            &f.srk,
            &a,
            &blobs,
            &OTHER_RP,
            GateKind::Uv,
            &salt1,
        ),
        "hmac-secret for another RP",
    );
}

mod support;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use passkey_tpm_core::tpm_iface::{CredProtect, GateKind, RpIdHash, TpmOps, Uid};
use passkey_tpm_tpm::adapter::TpmBackend;
use support::swtpm::Swtpm;

const RP: RpIdHash = RpIdHash([0x61; 32]);

fn state_dir(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("passkey-tpm-adapter-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn provisions_users_lazily_and_isolates_them() {
    let tpm = Swtpm::start();
    let dir = state_dir("isolate");
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    let alice = Uid(1000);
    // authd/Entra-style uid far beyond the NV range: indexes are allocated, not derived.
    let bob = Uid(1_879_048_193);

    let blobs = backend
        .create_credential(alice, &RP, CredProtect::UvOptional, false)
        .expect("create");
    let id = backend.credential_id(alice, &RP, &blobs).expect("id");
    assert_eq!(
        backend.open_credential_id(alice, &RP, &id).expect("open"),
        Some(blobs.clone())
    );
    assert_eq!(
        backend
            .open_credential_id(bob, &RP, &id)
            .expect("open as bob"),
        None
    );
    assert_eq!(
        backend
            .open_credential_id(alice, &RpIdHash([0; 32]), &id)
            .expect("open other rp"),
        None
    );

    let digest = [0x5c; 32];
    let der = backend
        .sign(alice, &blobs, &RP, GateKind::Uv, &digest)
        .expect("sign");
    let (x, y) = backend.public_key(&blobs).expect("public key");
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1)
        .expect("key")
        .verify_prehash(&digest, &Signature::from_der(&der).expect("der"))
        .expect("valid signature");

    assert!(
        backend
            .sign(bob, &blobs, &RP, GateKind::Uv, &digest)
            .is_err(),
        "bob can't use alice's key"
    );

    let mode = std::fs::metadata(dir.join("1000"))
        .expect("dir")
        .permissions();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
        0o700
    );
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn state_survives_a_broker_restart() {
    let tpm = Swtpm::start();
    let dir = state_dir("restart");
    let alice = Uid(1000);
    let (blobs, id) = {
        let mut backend = TpmBackend::new(tpm.context(), dir.clone());
        let blobs = backend
            .create_credential(alice, &RP, CredProtect::UvOptional, false)
            .expect("create");
        let id = backend.credential_id(alice, &RP, &blobs).expect("id");
        (blobs, id)
    };
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    assert_eq!(
        backend.open_credential_id(alice, &RP, &id).expect("open"),
        Some(blobs.clone())
    );
    backend
        .sign(alice, &blobs, &RP, GateKind::Uv, &[1; 32])
        .expect("sign after restart");
    backend.health().expect("healthy");
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn revoked_credentials_stop_opening_and_survive_restart() {
    let tpm = Swtpm::start();
    let dir = state_dir("revoke");
    let alice = Uid(1000);
    let (keep, gone) = {
        let mut backend = TpmBackend::new(tpm.context(), dir.clone());
        let a = backend
            .create_credential(alice, &RP, CredProtect::UvRequired, false)
            .expect("create");
        let b = backend
            .create_credential(alice, &RP, CredProtect::UvRequired, false)
            .expect("create");
        let keep = backend.credential_id(alice, &RP, &a).expect("id");
        let gone = backend.credential_id(alice, &RP, &b).expect("id");
        backend.revoke_credential(alice, &gone).expect("revoke");
        backend.revoke_credential(alice, &gone).expect("idempotent");
        assert_eq!(
            backend.open_credential_id(alice, &RP, &gone).expect("open"),
            None
        );
        (keep, gone)
    };
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    assert!(
        backend
            .open_credential_id(alice, &RP, &keep)
            .expect("open")
            .is_some(),
        "others unaffected"
    );
    assert_eq!(
        backend.open_credential_id(alice, &RP, &gone).expect("open"),
        None,
        "persisted"
    );
    std::fs::remove_dir_all(dir).expect("cleanup");
}

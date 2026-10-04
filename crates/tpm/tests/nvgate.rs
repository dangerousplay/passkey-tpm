mod support;

use passkey_tpm_tpm::nvgate::{self, Lockout};
use passkey_tpm_tpm::{policy, srk};
use support::swtpm::Swtpm;

const INDEX: u32 = nvgate::NV_BASE + 1;

#[test]
fn rotation_keeps_name_and_retires_old_secret() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let name = nvgate::define(&mut ctx, &srk, INDEX, Lockout::Protected, &[1; 32]).expect("define");
    assert_eq!(
        nvgate::name(&mut ctx, INDEX, Lockout::Protected).expect("name"),
        name
    );
    nvgate::check(&mut ctx, &srk, INDEX, &[1; 32]).expect("old secret accepted");

    let rotated = nvgate::rotate(
        &mut ctx,
        &srk,
        INDEX,
        Lockout::Protected,
        &[1; 32],
        &[2; 32],
    )
    .expect("rotate");
    assert_eq!(rotated, name, "credential policies reference this Name");
    assert!(
        nvgate::check(&mut ctx, &srk, INDEX, &[1; 32]).is_err(),
        "old secret must fail"
    );
    nvgate::check(&mut ctx, &srk, INDEX, &[2; 32]).expect("new secret accepted");
}

#[test]
fn rotate_with_wrong_old_secret_changes_nothing() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    nvgate::define(&mut ctx, &srk, INDEX, Lockout::Protected, &[1; 32]).expect("define");
    assert!(nvgate::rotate(
        &mut ctx,
        &srk,
        INDEX,
        Lockout::Protected,
        &[9; 32],
        &[2; 32]
    )
    .is_err());
    nvgate::check(&mut ctx, &srk, INDEX, &[1; 32]).expect("original secret still valid");
}

#[test]
fn lockout_attribute_is_part_of_the_public_area() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    nvgate::define(&mut ctx, &srk, INDEX, Lockout::Exempt, &[1; 32]).expect("define");
    assert!(
        nvgate::name(&mut ctx, INDEX, Lockout::Protected).is_err(),
        "DA flag mismatch detected"
    );
    nvgate::name(&mut ctx, INDEX, Lockout::Exempt).expect("matches");
}

#[test]
fn policy_secret_on_a_gate_matches_software_digest() {
    use tss_esapi::constants::SessionType;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::interface_types::session_handles::PolicySession;
    use tss_esapi::structures::SymmetricDefinition;

    for bus in ["firmware", "encrypted"] {
        std::env::set_var("PASSKEY_TPM_BUS_PROTECTION", bus);
        let tpm = Swtpm::start();
        let mut ctx = tpm.context();
        let srk = srk::ensure(&mut ctx).expect("SRK");
        let name =
            nvgate::define(&mut ctx, &srk, INDEX, Lockout::Exempt, &[7; 32]).expect("define");
        let policy_ref = [0x5a; 32];
        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("session")
            .expect("handle");
        let ps = PolicySession::try_from(session).expect("policy session");
        nvgate::satisfy(&mut ctx, &srk, ps, INDEX, &[7; 32], &policy_ref).expect("PolicySecret");
        let tpm_digest = ctx.policy_get_digest(ps).expect("digest");
        assert_eq!(
            tpm_digest.value(),
            policy::secret(&policy::ZERO, &name, &policy_ref).as_slice(),
            "{bus}"
        );
    }
    std::env::remove_var("PASSKEY_TPM_BUS_PROTECTION");
}

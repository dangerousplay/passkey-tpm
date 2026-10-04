//! Known-answer tests: the software policy calculator must match a real TPM trial session.

mod support;

use passkey_tpm_tpm::policy;
use support::swtpm::Swtpm;
use tss_esapi::constants::CommandCode;
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{Digest, DigestList, SymmetricDefinition};
use tss_esapi::Context;

fn trial(ctx: &mut Context) -> PolicySession {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("start trial session")
        .expect("session handle");
    PolicySession::try_from(session).expect("policy session")
}

fn digest(ctx: &mut Context, s: PolicySession) -> [u8; 32] {
    let d = ctx.policy_get_digest(s).expect("PolicyGetDigest");
    d.value().try_into().expect("32-byte digest")
}

#[test]
fn command_code_matches_tpm() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    for (code, tpm_code) in [
        (policy::cc::SIGN, CommandCode::Sign),
        (policy::cc::HMAC, CommandCode::Hmac),
    ] {
        let s = trial(&mut ctx);
        ctx.policy_command_code(s, tpm_code)
            .expect("PolicyCommandCode");
        assert_eq!(
            digest(&mut ctx, s),
            policy::command_code(&policy::ZERO, code)
        );
    }
}

#[test]
fn auth_value_matches_tpm() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let s = trial(&mut ctx);
    ctx.policy_command_code(s, CommandCode::NvChangeAuth)
        .expect("PolicyCommandCode");
    ctx.policy_auth_value(s).expect("PolicyAuthValue");
    let expected = policy::auth_value(&policy::command_code(
        &policy::ZERO,
        policy::cc::NV_CHANGE_AUTH,
    ));
    assert_eq!(digest(&mut ctx, s), expected);
}

#[test]
fn or_matches_tpm() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let a = policy::command_code(&policy::ZERO, policy::cc::SIGN);
    let b = policy::command_code(&policy::ZERO, policy::cc::HMAC);
    let c = policy::auth_value(&policy::ZERO);

    // The current digest must equal one branch before PolicyOR.
    let s = trial(&mut ctx);
    ctx.policy_command_code(s, CommandCode::Sign)
        .expect("PolicyCommandCode");
    let mut list = DigestList::new();
    for d in [a, b, c] {
        list.add(Digest::try_from(d.to_vec()).expect("digest"))
            .expect("add");
    }
    ctx.policy_or(s, list).expect("PolicyOR");
    assert_eq!(digest(&mut ctx, s), policy::or(&[a, b, c]).expect("or"));
}

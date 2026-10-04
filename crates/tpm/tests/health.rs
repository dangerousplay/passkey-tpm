mod support;

use passkey_tpm_core::tpm_iface::{CredProtect, GateKind, RpIdHash, TpmError};
use passkey_tpm_tpm::gates::GateIndexes;
use passkey_tpm_tpm::sign::{self, UserGates};
use passkey_tpm_tpm::{credential, gates, health, nvgate, pin, srk};
use support::swtpm::Swtpm;
use tss_esapi::handles::AuthHandle;

#[test]
fn tpm_15_clear_is_reported_as_reset_without_panicking() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let store = gates::provision(
        &mut ctx,
        &srk,
        GateIndexes {
            pin: nvgate::NV_BASE + 3,
            uv: nvgate::NV_BASE + 4,
            up: nvgate::NV_BASE + 5,
        },
    )
    .expect("provision");
    let names = gates::names(&mut ctx, &store).expect("names");
    let rp = RpIdHash([5; 32]);
    let blobs = credential::create(&mut ctx, &srk, &names, &rp, CredProtect::UvOptional, false)
        .expect("create");
    health::check(&mut ctx, &store.srk_name).expect("healthy");

    ctx.execute_with_nullauth_session(|ctx| ctx.clear(AuthHandle::Platform))
        .expect("TPM2_Clear");

    let err = health::check(&mut ctx, &store.srk_name).expect_err("cleared TPM");
    assert_eq!(err.to_tpm_error(), TpmError::Reset);

    // Re-provisioning creates a *different* SRK, so old credentials stay dead and are
    // reported as unknown rather than crashing.
    let new_srk = srk::ensure(&mut ctx).expect("new SRK");
    assert_ne!(new_srk.name, store.srk_name);
    let user = UserGates {
        store: &store,
        names: &names,
    };
    let err = sign::sign(
        &mut ctx,
        &new_srk,
        &user,
        &blobs,
        &rp,
        GateKind::Uv,
        &[0; 32],
    )
    .expect_err("dead credential");
    assert_ne!(err.to_tpm_error(), TpmError::Unavailable, "{err}");
}

#[test]
fn tpm_14_da_status_reports_lockout_auth_and_counts_pin_failures() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let store = gates::provision(
        &mut ctx,
        &srk,
        GateIndexes {
            pin: nvgate::NV_BASE + 6,
            uv: nvgate::NV_BASE + 7,
            up: nvgate::NV_BASE + 8,
        },
    )
    .expect("provision");
    let store = pin::set_pin(&mut ctx, &srk, &store, &[1; 16]).expect("setPIN");

    let before = health::da_status(&mut ctx).expect("status");
    assert!(
        !before.lockout_auth_set,
        "fresh swtpm has no lockout password: warn the admin"
    );
    assert!(!before.in_lockout);

    let err = pin::verify(&mut ctx, &srk, &store, &[9; 16]).expect_err("wrong PIN");
    assert_eq!(err.to_tpm_error(), TpmError::WrongPin);

    let after = health::da_status(&mut ctx).expect("status");
    assert_eq!(
        after.failed_tries,
        before.failed_tries + 1,
        "PIN gate is DA-protected"
    );
}

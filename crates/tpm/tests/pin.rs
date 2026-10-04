mod support;

use passkey_tpm_core::tpm_iface::{CredProtect, GateKind, RpIdHash, TpmError};
use passkey_tpm_tpm::gates::GateIndexes;
use passkey_tpm_tpm::sign::{self, UserGates};
use passkey_tpm_tpm::{credential, gates, nvgate, pin, srk};
use support::swtpm::Swtpm;

const RP: RpIdHash = RpIdHash([0x33; 32]);
const PIN_1234: [u8; 16] = [1; 16];
const PIN_5678: [u8; 16] = [2; 16];

fn indexes(base: u32) -> GateIndexes {
    GateIndexes {
        pin: nvgate::NV_BASE + base,
        uv: nvgate::NV_BASE + base + 1,
        up: nvgate::NV_BASE + base + 2,
    }
}

#[test]
fn tpm_09_pin_changes_keep_existing_credentials() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let store = gates::provision(&mut ctx, &srk, indexes(70)).expect("provision");
    let names = gates::names(&mut ctx, &store).expect("names");
    let blobs = credential::create(&mut ctx, &srk, &names, &RP, CredProtect::UvRequired, false)
        .expect("create");
    let id_before = blobs.encode().expect("encode");

    assert!(
        pin::verify(&mut ctx, &srk, &store, &PIN_1234).is_err(),
        "no PIN set yet"
    );
    let store = pin::set_pin(&mut ctx, &srk, &store, &PIN_1234).expect("setPIN");
    assert!(store.pin_bootstrap.is_none());
    assert!(
        pin::set_pin(&mut ctx, &srk, &store, &PIN_5678).is_err(),
        "setPIN only once"
    );
    pin::verify(&mut ctx, &srk, &store, &PIN_1234).expect("PIN 1234 verifies");

    let store = pin::change_pin(&mut ctx, &srk, &store, &PIN_1234, &PIN_5678).expect("changePIN");
    pin::verify(&mut ctx, &srk, &store, &PIN_5678).expect("new PIN verifies");
    let err = pin::verify(&mut ctx, &srk, &store, &PIN_1234).expect_err("old PIN must fail");
    assert_eq!(err.to_tpm_error(), TpmError::WrongPin);

    // After PIN verification the UV gate signs; the credential is untouched by PIN changes.
    let user = UserGates {
        store: &store,
        names: &names,
    };
    sign::sign(&mut ctx, &srk, &user, &blobs, &RP, GateKind::Pin, &[4; 32])
        .expect("sign after PIN");
    assert_eq!(
        gates::names(&mut ctx, &store).expect("names"),
        names,
        "gate Names unchanged"
    );
    assert_eq!(
        blobs.encode().expect("encode"),
        id_before,
        "credential ID unchanged"
    );
}

#[test]
fn change_pin_with_wrong_old_pin_changes_nothing() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let store = gates::provision(&mut ctx, &srk, indexes(80)).expect("provision");
    let store = pin::set_pin(&mut ctx, &srk, &store, &PIN_1234).expect("setPIN");
    assert!(pin::change_pin(&mut ctx, &srk, &store, &PIN_5678, &[3; 16]).is_err());
    pin::verify(&mut ctx, &srk, &store, &PIN_1234).expect("original PIN still valid");
}

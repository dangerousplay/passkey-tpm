//! HARD-05: one uid can't drive the TPM-wide dictionary-attack counter to lockout by
//! cycling setPIN, wrong PINs and authenticatorReset.

mod support;

use passkey_tpm_core::tpm_iface::{TpmError, TpmOps, Uid};
use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_tpm::health;
use support::swtpm::Swtpm;

const ALICE: Uid = Uid(1000);
const BOB: Uid = Uid(1001);
const PIN: [u8; 16] = [1; 16];
const WRONG: [u8; 16] = [9; 16];

fn state_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("passkey-tpm-da-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Runs setPIN, up to 8 wrong PINs and authenticatorReset until a wrong PIN is refused
/// with `Lockout`, checking the TPM never reaches lockout. Returns `(cycle, attempt)` of the
/// refusal.
fn reset_loop(tpm: &Swtpm, dir: &std::path::Path) -> (u32, u32) {
    let max_tries = health::da_status(&mut tpm.context())
        .expect("DA status")
        .max_tries;
    for cycle in 0..=max_tries / 8 + 1 {
        let mut backend = TpmBackend::new(tpm.context(), dir.to_path_buf());
        backend.change_pin(ALICE, None, &PIN).expect("setPIN");
        let mut refused = None;
        for attempt in 0..8 {
            match backend.verify_pin(ALICE, &WRONG) {
                Err(TpmError::WrongPin) => {}
                Err(TpmError::Lockout) => {
                    refused = Some(attempt);
                    break;
                }
                other => panic!("cycle {cycle}: unexpected {other:?}"),
            }
        }
        backend.reset_user(ALICE).expect("authenticatorReset");
        drop(backend);
        let da = health::da_status(&mut tpm.context()).expect("DA status");
        assert!(
            !da.in_lockout && da.failed_tries < da.max_tries,
            "cycle {cycle}: TPM DA counter {} of {}",
            da.failed_tries,
            da.max_tries
        );
        if let Some(attempt) = refused {
            return (cycle, attempt);
        }
    }
    panic!("the setPIN / wrong PIN / reset loop was never stopped");
}

#[test]
fn reset_does_not_refill_the_wrong_pin_budget() {
    let tpm = Swtpm::start();
    // A CTAP-compatible TPM (AD-010); no failure is forgiven during the test.
    tpm.set_da_parameters(32, 3600, 3600);
    let dir = state_dir("reset-loop");
    assert_eq!(
        health::da_status(&mut tpm.context()).expect("DA").max_tries,
        32
    );

    // All 8 CTAP retries are available in the first cycle; after the reset none are left.
    assert_eq!(reset_loop(&tpm, &dir), (1, 0));

    // Other users keep their own budget.
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    backend.change_pin(BOB, None, &PIN).expect("bob setPIN");
    assert_eq!(backend.verify_pin(BOB, &WRONG), Err(TpmError::WrongPin));
    assert_eq!(backend.verify_pin(BOB, &PIN), Ok(()));
    // Alice's correct PIN is refused too while her budget is spent: nothing reaches the TPM.
    backend.change_pin(ALICE, None, &PIN).expect("alice setPIN");
    assert_eq!(backend.verify_pin(ALICE, &PIN), Err(TpmError::Lockout));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn budget_stays_below_a_small_max_tries() {
    // swtpm's default maxTries is 3, below what AD-010 requires: the budget shrinks to fit.
    let tpm = Swtpm::start();
    let dir = state_dir("small");
    assert_eq!(reset_loop(&tpm, &dir), (0, 2));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

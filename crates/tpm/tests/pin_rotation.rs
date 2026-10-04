//! Crash safety of PIN changes (HARD-06): the broker is killed after each step of a PIN
//! rotation; on restart the PIN is the old or the new one, never unusable.

mod support;

use passkey_tpm_core::tpm_iface::{TpmError, TpmOps, Uid};
use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_tpm::nvgate::{self, Lockout};
use passkey_tpm_tpm::{pin, srk};
use passkey_tpm_wire::gatestore::GateStore;
use support::swtpm::Swtpm;

const ALICE: Uid = Uid(1000);
const OLD: [u8; 16] = [1; 16];
const NEW: [u8; 16] = [2; 16];
const NEXT: [u8; 16] = [3; 16];

/// The steps of a PIN change, in order; the broker dies right after the named one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrashAfter {
    /// Old PIN checked, nothing persisted yet.
    Begin,
    /// New PIN persisted as pending; the NV index is untouched.
    PersistPending,
    /// PIN NV index undefined.
    Undefine,
    /// PIN NV index defined with the new secret; the pending marker is still on disk.
    Define,
    /// Pending marker cleared.
    PersistDone,
}

fn state_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "passkey-tpm-pin-rotation-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn write(dir: &std::path::Path, store: &GateStore) {
    std::fs::write(
        dir.join("1000").join("gates.v1"),
        store.encode().expect("encode"),
    )
    .expect("write gates.v1");
}

/// Sets `OLD` as the PIN (or leaves it unset), then runs a change to `NEW` up to `crash`.
fn interrupted_change(tpm: &Swtpm, dir: &std::path::Path, pin_was_set: bool, crash: CrashAfter) {
    {
        let mut backend = TpmBackend::new(tpm.context(), dir.to_path_buf());
        if pin_was_set {
            backend.change_pin(ALICE, None, &OLD).expect("setPIN");
        } else {
            // Provision without a PIN.
            assert_eq!(backend.pin_is_set(ALICE), Ok(false));
            backend
                .create_credential(
                    ALICE,
                    &passkey_tpm_core::tpm_iface::RpIdHash([0; 32]),
                    passkey_tpm_core::tpm_iface::CredProtect::UvRequired,
                    false,
                )
                .expect("provision");
        }
    }
    let store = GateStore::decode(&std::fs::read(dir.join("1000/gates.v1")).expect("read"))
        .expect("decode");
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let pending = if pin_was_set {
        pin::begin_change(&mut ctx, &srk, &store, &OLD, &NEW)
    } else {
        pin::begin_set(&mut ctx, &srk, &store, &NEW)
    }
    .expect("begin");
    if crash == CrashAfter::Begin {
        return;
    }
    write(dir, &pending);
    if crash == CrashAfter::PersistPending {
        return;
    }
    nvgate::undefine(&mut ctx, store.pin_nv_index).expect("undefine");
    if crash == CrashAfter::Undefine {
        return;
    }
    let new_auth = &pending.pending_pin.as_ref().expect("pending").auth.0;
    nvgate::define(
        &mut ctx,
        &srk,
        store.pin_nv_index,
        Lockout::Protected,
        new_auth,
    )
    .expect("define");
    if crash == CrashAfter::Define {
        return;
    }
    let done = pin::complete(&mut ctx, &srk, &pending).expect("complete is idempotent");
    write(dir, &done);
}

#[test]
fn pin_change_survives_a_crash_after_every_step() {
    for crash in [
        CrashAfter::Begin,
        CrashAfter::PersistPending,
        CrashAfter::Undefine,
        CrashAfter::Define,
        CrashAfter::PersistDone,
    ] {
        let tpm = Swtpm::start();
        let dir = state_dir(&format!("{crash:?}"));
        interrupted_change(&tpm, &dir, true, crash);

        let mut backend = TpmBackend::new(tpm.context(), dir.clone());
        let (current, other) = if crash == CrashAfter::Begin {
            (OLD, NEW)
        } else {
            (NEW, OLD)
        };
        assert_eq!(backend.verify_pin(ALICE, &current), Ok(()), "{crash:?}");
        assert_eq!(
            backend.verify_pin(ALICE, &other),
            Err(TpmError::WrongPin),
            "{crash:?}"
        );
        backend
            .change_pin(ALICE, Some(&current), &NEXT)
            .unwrap_or_else(|e| panic!("{crash:?}: PIN can still be changed: {e:?}"));
        assert_eq!(backend.verify_pin(ALICE, &NEXT), Ok(()), "{crash:?}");
        let on_disk = GateStore::decode(&std::fs::read(dir.join("1000/gates.v1")).expect("read"))
            .expect("decode");
        assert_eq!(on_disk.pending_pin, None, "{crash:?}: marker cleared");
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}

#[test]
fn first_pin_survives_a_crash_after_undefine() {
    let tpm = Swtpm::start();
    let dir = state_dir("set-undefine");
    interrupted_change(&tpm, &dir, false, CrashAfter::Undefine);
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    assert_eq!(backend.pin_is_set(ALICE), Ok(true));
    assert_eq!(backend.verify_pin(ALICE, &NEW), Ok(()));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

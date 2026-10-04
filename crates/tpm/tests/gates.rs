mod support;

use passkey_tpm_tpm::gates::{self, GateIndexes};
use passkey_tpm_tpm::nvgate::{self, Lockout};
use passkey_tpm_tpm::srk;
use support::swtpm::Swtpm;
use tss_esapi::handles::{NvIndexTpmHandle, TpmHandle};

fn indexes(base: u32) -> GateIndexes {
    GateIndexes {
        pin: nvgate::NV_BASE + base,
        uv: nvgate::NV_BASE + base + 1,
        up: nvgate::NV_BASE + base + 2,
    }
}

fn no_da(ctx: &mut tss_esapi::Context, index: u32) -> bool {
    let nv = ctx
        .tr_from_tpm_public(TpmHandle::NvIndex(
            NvIndexTpmHandle::new(index).expect("idx"),
        ))
        .expect("tr");
    ctx.nv_read_public(nv.into())
        .expect("nv_read_public")
        .0
        .attributes()
        .no_da()
}

#[test]
fn users_get_distinct_gates_with_correct_da_flags() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let a = gates::provision(&mut ctx, &srk, indexes(10)).expect("provision A");
    let b = gates::provision(&mut ctx, &srk, indexes(20)).expect("provision B");
    let na = gates::names(&mut ctx, &a).expect("names A");
    let nb = gates::names(&mut ctx, &b).expect("names B");
    assert_ne!(na.uv, nb.uv);
    assert_ne!(na.up, nb.up);
    assert_ne!(na.uv, na.up);
    assert_ne!(a.uv.auth, b.uv.auth);
    assert_eq!(a.srk_name, srk.name);
    assert!(a.pin_bootstrap.is_some(), "no PIN set yet");
    assert!(!no_da(&mut ctx, a.pin_nv_index), "PIN gate is DA-protected");
    assert!(no_da(&mut ctx, a.uv.nv_index), "UV gate is noDA");
    assert!(no_da(&mut ctx, a.up.nv_index), "UP gate is noDA");
    nvgate::check(&mut ctx, &srk, a.uv.nv_index, &a.uv.auth.0).expect("UV secret works");
    assert!(
        nvgate::check(&mut ctx, &srk, a.uv.nv_index, &b.uv.auth.0).is_err(),
        "B's secret fails on A's gate"
    );
    let _ = Lockout::Exempt;
}

#[test]
fn gate_store_survives_a_round_trip_through_disk_format_and_removal_works() {
    let tpm = Swtpm::start();
    let mut ctx = tpm.context();
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let store = gates::provision(&mut ctx, &srk, indexes(30)).expect("provision");
    let reloaded = passkey_tpm_wire::gatestore::GateStore::decode(&store.encode().expect("encode"))
        .expect("decode");
    assert_eq!(
        gates::names(&mut ctx, &store).expect("names"),
        gates::names(&mut ctx, &reloaded).expect("again")
    );
    gates::remove(&mut ctx, &store).expect("remove");
    assert!(gates::names(&mut ctx, &store).is_err(), "gates gone");
}

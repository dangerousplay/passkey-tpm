//! Assertion latency benchmark (TPM-17). Run with `cargo xtask bench-tpm`.
//!
//! Uses a private swtpm by default. To measure real hardware set
//! `PASSKEY_TPM_BENCH_TCTI=device:/dev/tpmrm0`: this reuses (or creates) the standard SRK at
//! 0x81000001 and defines, then removes, one NV index.

mod support;

use std::str::FromStr;
use std::time::{Duration, Instant};

use passkey_tpm_core::tpm_iface::{CredProtect, GateKind, RpIdHash};
use passkey_tpm_tpm::gates::GateIndexes;
use passkey_tpm_tpm::sign::{self, UserGates};
use passkey_tpm_tpm::{credential, gates, nvgate, srk};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

const RUNS: usize = 50;
const BENCH_NV: u32 = nvgate::NV_BASE + 0xBEE0;

fn percentile(samples: &mut [Duration], p: usize) -> Duration {
    samples.sort();
    let idx = (samples.len() * p / 100).min(samples.len() - 1);
    samples[idx]
}

fn measure(label: &str, mut f: impl FnMut()) {
    let mut samples: Vec<Duration> = (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed()
        })
        .collect();
    let p50 = percentile(&mut samples, 50);
    let p95 = percentile(&mut samples, 95);
    eprintln!(
        "{label:<28} p50 {:>7.1} ms   p95 {:>7.1} ms",
        p50.as_secs_f64() * 1e3,
        p95.as_secs_f64() * 1e3
    );
}

fn report(ctx: &mut Context) {
    use tss_esapi::constants::PropertyTag;
    let prop = |ctx: &mut Context, tag| ctx.get_tpm_property(tag).ok().flatten().unwrap_or(0);
    let vendor = prop(ctx, PropertyTag::Manufacturer).to_be_bytes();
    let fw1 = prop(ctx, PropertyTag::FirmwareVersion1);
    let fw2 = prop(ctx, PropertyTag::FirmwareVersion2);
    eprintln!(
        "TPM manufacturer {:?}, firmware {fw1:#010x}.{fw2:#010x}",
        String::from_utf8_lossy(&vendor)
    );
    match passkey_tpm_tpm::health::da_status(ctx) {
        Ok(da) => eprintln!(
            "DA: {da:?} (CTAP-compatible: {})",
            da.compatible_with_ctap()
        ),
        Err(e) => eprintln!("DA status unavailable: {e}"),
    }
    eprintln!(
        "SRK present before run: {}",
        passkey_tpm_tpm::srk::open(ctx).is_ok()
    );
}

#[test]
#[ignore = "benchmark: run with `cargo xtask bench-tpm`"]
fn assertion_latency() {
    let swtpm;
    let mut ctx = match std::env::var("PASSKEY_TPM_BENCH_TCTI") {
        Ok(tcti) => {
            eprintln!("benchmarking {tcti}");
            Context::new(TctiNameConf::from_str(&tcti).expect("TCTI")).expect("connect")
        }
        Err(_) => {
            eprintln!("benchmarking swtpm (set PASSKEY_TPM_BENCH_TCTI for real hardware)");
            swtpm = support::swtpm::Swtpm::start();
            swtpm.context()
        }
    };
    report(&mut ctx);
    let srk = srk::ensure(&mut ctx).expect("SRK");
    let store = gates::provision(
        &mut ctx,
        &srk,
        GateIndexes {
            pin: BENCH_NV,
            uv: BENCH_NV + 1,
            up: BENCH_NV + 2,
        },
    )
    .expect("provision");
    let names = gates::names(&mut ctx, &store).expect("names");
    let user = UserGates {
        store: &store,
        names: &names,
    };
    let rp = RpIdHash([7; 32]);
    let blobs = credential::create(&mut ctx, &srk, &names, &rp, CredProtect::UvOptional, true)
        .expect("create");

    measure("makeCredential (+hmac keys)", || {
        credential::create(&mut ctx, &srk, &names, &rp, CredProtect::UvOptional, true)
            .expect("create");
    });
    measure("getAssertion sign (UV gate)", || {
        sign::sign(&mut ctx, &srk, &user, &blobs, &rp, GateKind::Uv, &[1; 32]).expect("sign");
    });
    measure("hmac-secret (UV gate)", || {
        sign::hmac(&mut ctx, &srk, &user, &blobs, &rp, GateKind::Uv, &[2; 32]).expect("hmac");
    });

    // Leave no state behind except the shared SRK.
    gates::remove(&mut ctx, &store).expect("remove bench gates");
}

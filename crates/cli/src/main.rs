//! `passkey-tpm`: administration of passkey-tpm.
//!
//! ```text
//! passkey-tpm version                             package version
//! passkey-tpm info                                diagnostics report for bug reports
//! passkey-tpm tpm status                          TPM type, SRK and dictionary-attack state
//! passkey-tpm user remove --uid N [--state-dir D] remove a user's gates and state
//! ```
//! `PASSKEY_TPM_TCTI` selects the TPM (default `device:/dev/tpmrm0`).
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod info;

use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use passkey_tpm_tpm::{gates, health, nvgate, srk};
use passkey_tpm_wire::gatestore::GateStore;
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

const USAGE: &str = "usage:
  passkey-tpm version
  passkey-tpm info
  passkey-tpm tpm status
  passkey-tpm user remove --uid N [--state-dir DIR]";

/// Package version and target, e.g. `0.1.0 (x86_64-linux)`.
fn version() -> String {
    format!(
        "{} ({}-{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

fn context() -> Result<Context, String> {
    let tcti =
        std::env::var("PASSKEY_TPM_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".to_owned());
    let tcti =
        TctiNameConf::from_str(&tcti).map_err(|e| format!("invalid PASSKEY_TPM_TCTI: {e}"))?;
    Context::new(tcti).map_err(|e| format!("cannot open TPM: {e}"))
}

fn tpm_status() -> Result<(), String> {
    let mut ctx = context()?;
    match srk::open(&mut ctx) {
        Ok(s) => println!(
            "SRK: present at {:#010x}, bus protection {:?}",
            srk::SRK_HANDLE,
            s.bus
        ),
        Err(e) => println!("SRK: {e} (created on first use if the slot is empty)"),
    }
    let used = nv_indexes(&mut ctx)?;
    println!("passkey-tpm NV indexes in use: {}", used.len());
    for index in used {
        println!("  {index:#010x}");
    }
    let da = health::da_status(&mut ctx).map_err(|e| e.to_string())?;
    println!(
        "dictionary-attack: {} of {} failures, recovery {} s, in lockout: {}",
        da.failed_tries, da.max_tries, da.recovery_interval_s, da.in_lockout
    );
    if !da.lockout_auth_set {
        println!("WARNING: no lockout password is set; any TPM user can reset the DA counter, weakening PIN protection.");
    }
    if !da.compatible_with_ctap() {
        println!(
            "WARNING: DA max tries ({}) must exceed the CTAP PIN retry limit (8).",
            da.max_tries
        );
    }
    Ok(())
}

/// NV indexes defined in passkey-tpm's allocation range.
fn nv_indexes(ctx: &mut Context) -> Result<Vec<u32>, String> {
    use tss_esapi::constants::CapabilityType;
    use tss_esapi::structures::CapabilityData;
    let (data, _) = ctx
        .execute_without_session(|ctx| {
            ctx.get_capability(CapabilityType::Handles, nvgate::NV_BASE, 1024)
        })
        .map_err(|e| e.to_string())?;
    let CapabilityData::Handles(list) = data else {
        return Err("unexpected capability data".into());
    };
    Ok(list
        .iter()
        .map(|h| u32::from(*h))
        .filter(|h| (nvgate::NV_BASE..=nvgate::NV_LAST).contains(h))
        .collect())
}

fn user_remove(args: &[String]) -> Result<(), String> {
    let mut uid = None;
    let mut state_dir = PathBuf::from("/var/lib/passkey-tpm");
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--uid" => uid = it.next().and_then(|v| v.parse::<u32>().ok()),
            "--state-dir" => {
                state_dir = it
                    .next()
                    .map(PathBuf::from)
                    .ok_or("--state-dir needs a value")?;
            }
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    let uid = uid.ok_or("--uid N is required")?;
    let dir = state_dir.join(uid.to_string());
    let bytes = std::fs::read(dir.join("gates.v1"))
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let store = GateStore::decode(&bytes).map_err(|e| format!("corrupt gates.v1: {e:?}"))?;
    let mut ctx = context()?;
    gates::remove(&mut ctx, &store).map_err(|e| format!("cannot remove gates: {e}"))?;
    std::fs::remove_dir_all(&dir).map_err(|e| format!("cannot remove {}: {e}", dir.display()))?;
    println!(
        "removed user {uid}: gates {:#x}, {:#x}, {:#x}",
        store.pin_nv_index, store.uv.nv_index, store.up.nv_index
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["version" | "--version" | "-V"] => {
            println!("passkey-tpm {}", version());
            Ok(())
        }
        ["info"] => {
            print!("{}", info::render(&info::collect()));
            Ok(())
        }
        ["tpm", "status"] => tpm_status(),
        ["user", "remove", ..] => user_remove(args.get(2..).unwrap_or_default()),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

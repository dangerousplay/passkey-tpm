//! `passkey-tpm`: administration of passkey-tpm.
//!
//! ```text
//! passkey-tpm version                             package version
//! passkey-tpm info                                diagnostics report for bug reports
//! passkey-tpm tpm status                          TPM type, SRK and dictionary-attack state
//! passkey-tpm user remove --uid N [--state-dir D] [--force]
//!                                                 remove a user's gates and state
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
  passkey-tpm user remove --uid N [--state-dir DIR] [--force]";

/// Well-known name of the broker (`passkey_tpm_uvd::BUS_NAME`, checked by a test).
const BROKER_BUS_NAME: &str = "io.github.dangerousplay.PasskeyTpm1";

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

/// Whether the broker currently owns its name on the bus `conn`.
async fn broker_running(conn: &zbus::Connection) -> Result<bool, String> {
    let dbus = zbus::fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| e.to_string())?;
    let name = zbus::names::BusName::try_from(BROKER_BUS_NAME).map_err(|e| e.to_string())?;
    dbus.name_has_owner(name).await.map_err(|e| e.to_string())
}

/// Asks the system bus whether passkey-tpm-uvd is running.
fn system_broker_running() -> Result<bool, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start runtime: {e}"))?;
    runtime.block_on(async {
        let conn = zbus::Connection::system()
            .await
            .map_err(|e| format!("system bus unavailable: {e}"))?;
        broker_running(&conn).await
    })
}

/// `user remove` must not run under the broker (HARD-18): uvd caches each user's
/// `GateStore` in memory and would keep serving the user from the removed gates' stale
/// copy. An unknown answer counts as running.
fn refuse_while_broker_runs(running: Result<bool, String>, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    match running {
        Ok(false) => Ok(()),
        Ok(true) => Err(
            "passkey-tpm-uvd is running and caches user state; stop it first \
             (systemctl stop passkey-tpm-uvd), or pass --force"
                .to_owned(),
        ),
        Err(e) => Err(format!(
            "cannot tell whether passkey-tpm-uvd is running ({e}); make sure it is stopped \
             and pass --force"
        )),
    }
}

fn user_remove(args: &[String]) -> Result<(), String> {
    let mut uid = None;
    let mut force = false;
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
            "--force" => force = true,
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    let uid = uid.ok_or("--uid N is required")?;
    let running = if force {
        Ok(false)
    } else {
        system_broker_running()
    };
    refuse_while_broker_runs(running, force)?;
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

#[cfg(test)]
mod tests {
    use passkey_tpm_testkit::bus::PrivateBus;

    use super::{broker_running, refuse_while_broker_runs, BROKER_BUS_NAME};

    #[test]
    fn bus_name_matches_the_broker() {
        assert_eq!(BROKER_BUS_NAME, passkey_tpm_uvd::BUS_NAME);
    }

    #[tokio::test]
    async fn detects_a_running_broker_by_its_bus_name() {
        let bus = PrivateBus::start();
        let cli = bus.connect().await;
        assert_eq!(broker_running(&cli).await, Ok(false));
        let broker = bus.connect().await;
        broker
            .request_name(BROKER_BUS_NAME)
            .await
            .expect("own name");
        assert_eq!(broker_running(&cli).await, Ok(true));
        drop(broker);
        // The bus drops the name with the connection; give it a moment.
        for _ in 0..50 {
            if broker_running(&cli).await == Ok(false) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("name still owned after the broker disconnected");
    }

    #[test]
    fn user_remove_is_refused_while_the_broker_runs_unless_forced() {
        // HARD-18: uvd caches each user's GateStore, so removing a user under it leaves
        // stale gates in memory.
        let refused = refuse_while_broker_runs(Ok(true), false).unwrap_err();
        assert!(refused.contains("passkey-tpm-uvd"), "{refused}");
        assert!(refused.contains("--force"), "{refused}");
        assert_eq!(refuse_while_broker_runs(Ok(true), true), Ok(()));
        assert_eq!(refuse_while_broker_runs(Ok(false), false), Ok(()));
        assert!(
            refuse_while_broker_runs(Err("no bus".into()), false).is_err(),
            "unknown counts as running"
        );
        assert_eq!(refuse_while_broker_runs(Err("no bus".into()), true), Ok(()));
    }
}

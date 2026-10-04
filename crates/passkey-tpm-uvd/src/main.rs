//! `passkey-tpm-uvd`: the passkey-tpm broker daemon (system service).
#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_uvd::{serve, Broker, NssUsers, TpmWorker};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> ExitCode {
    let state_dir = std::env::var_os("STATE_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/passkey-tpm"));
    let tcti =
        std::env::var("PASSKEY_TPM_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".to_owned());
    let tcti = match TctiNameConf::from_str(&tcti) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("invalid PASSKEY_TPM_TCTI: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Fail early if the TPM is unreachable, then hand the context to the worker thread.
    if let Err(e) = Context::new(tcti.clone()) {
        eprintln!("cannot open TPM: {e}");
        return ExitCode::FAILURE;
    }
    let worker = match TpmWorker::spawn(move || {
        let ctx = Context::new(tcti).unwrap_or_else(|e| {
            eprintln!("cannot open TPM: {e}");
            std::process::exit(1);
        });
        TpmBackend::new(ctx, state_dir)
    }) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot start TPM worker: {e}");
            return ExitCode::FAILURE;
        }
    };

    let conn = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot connect to the system bus: {e}");
            return ExitCode::FAILURE;
        }
    };
    let broker = Broker::new(worker, conn.clone(), Box::new(NssUsers), VERIFY_TIMEOUT);
    if let Err(e) = serve(&conn, broker).await {
        eprintln!("cannot export the broker: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("passkey-tpm-uvd ready");
    let _ = tokio::signal::ctrl_c().await;
    ExitCode::SUCCESS
}

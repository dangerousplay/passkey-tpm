//! Test-only fake fprintd on the system bus (or `DBUS_SYSTEM_BUS_ADDRESS`), used by the
//! end-to-end harness on machines without a fingerprint reader. Every verification matches
//! after `MOCK_FPRINTD_DELAY_MS` (default 300). Never install this.
#![allow(clippy::print_stderr)]

use std::time::Duration;

use passkey_tpm_uv::mock::{self, MockFprintd};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let delay = std::env::var("MOCK_FPRINTD_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let conn = zbus::Connection::system().await.expect("bus");
    let _handle = mock::serve(
        &conn,
        MockFprintd::with_results(&["verify-match"], Duration::from_millis(delay)),
    )
    .await
    .expect("serve mock fprintd");
    eprintln!("mock fprintd ready (auto-match after {delay} ms)");
    std::future::pending::<()>().await;
}

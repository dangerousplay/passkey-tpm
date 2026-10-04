//! fprintd client tests against the mock fprintd on a private `dbus-daemon` per test.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use passkey_tpm_uv::fprintd::{self, UvResult, DEVICE_IFACE};
use passkey_tpm_uv::mock::{self, MockFprintd, MockHandle, DEVICE_PATH};
use tokio_util::sync::CancellationToken;
use zbus::Connection;

const USER: &str = "alice";

/// A private bus daemon, killed on drop.
struct PrivateBus {
    child: Child,
    config: PathBuf,
    address: String,
}

impl PrivateBus {
    fn start() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let config = std::env::temp_dir().join(format!(
            "passkey-tpm-uv-bus-{}-{}.conf",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &config,
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
        )
        .unwrap();
        let mut child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .args(["--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn dbus-daemon");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line.trim().to_owned();
        assert!(!address.is_empty(), "dbus-daemon printed no address");
        Self {
            child,
            config,
            address,
        }
    }

    async fn connect(&self) -> Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

struct Fixture {
    _bus: PrivateBus,
    client: Connection,
    _service: Connection,
    mock: MockHandle,
    bus_address: String,
}

async fn fixture(script: MockFprintd) -> Fixture {
    let bus = PrivateBus::start();
    let service = bus.connect().await;
    let mock = mock::serve(&service, script).await.unwrap();
    let client = bus.connect().await;
    let bus_address = bus.address.clone();
    Fixture {
        _bus: bus,
        client,
        _service: service,
        mock,
        bus_address,
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

async fn verify(f: &Fixture, timeout: Duration) -> UvResult {
    fprintd::verify(&f.client, USER, timeout, CancellationToken::new()).await
}

fn assert_cleaned_up(f: &Fixture) {
    let calls = f.mock.calls();
    assert_eq!(calls.claims, vec![USER.to_owned()]);
    assert_eq!(calls.verify_starts, vec!["any".to_owned()]);
    assert_eq!(calls.verify_stops, 1, "VerifyStop must be called once");
    assert_eq!(calls.releases, 1, "Release must be called once");
    assert!(!f.mock.is_claimed());
    assert!(!f.mock.is_verifying());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn match_result() {
    let f = fixture(MockFprintd::with_results(&["verify-match"], ms(20))).await;
    assert_eq!(verify(&f, Duration::from_secs(5)).await, UvResult::Match);
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_match_result() {
    let f = fixture(MockFprintd::with_results(&["verify-no-match"], ms(20))).await;
    assert_eq!(verify(&f, Duration::from_secs(5)).await, UvResult::NoMatch);
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_then_match() {
    let f = fixture(MockFprintd::with_results(
        &[
            "verify-retry-scan",
            "verify-swipe-too-short",
            "verify-finger-not-centered",
            "verify-remove-and-retry",
            "verify-match",
        ],
        ms(20),
    ))
    .await;
    assert_eq!(verify(&f, Duration::from_secs(5)).await, UvResult::Match);
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_then_no_match() {
    let f = fixture(MockFprintd::with_results(
        &["verify-retry-scan", "verify-no-match", "verify-match"],
        ms(20),
    ))
    .await;
    assert_eq!(verify(&f, Duration::from_secs(5)).await, UvResult::NoMatch);
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_error_is_unavailable() {
    let f = fixture(MockFprintd::with_results(&["verify-unknown-error"], ms(20))).await;
    assert!(matches!(
        verify(&f, Duration::from_secs(5)).await,
        UvResult::Unavailable(_)
    ));
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnected_is_unavailable() {
    let f = fixture(MockFprintd::with_results(&["verify-disconnected"], ms(20))).await;
    assert!(matches!(
        verify(&f, Duration::from_secs(5)).await,
        UvResult::Unavailable(_)
    ));
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_mid_verify() {
    let f = fixture(MockFprintd::with_results(&[], ms(20))).await;
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let mock = f.mock.clone();
    tokio::spawn(async move {
        // Cancel only once the scan is running.
        while !mock.is_verifying() {
            tokio::time::sleep(ms(5)).await;
        }
        trigger.cancel();
    });
    let r = fprintd::verify(&f.client, USER, Duration::from_secs(10), cancel).await;
    assert_eq!(r, UvResult::Cancelled);
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_before_start_claims_nothing() {
    let f = fixture(MockFprintd::default()).await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let r = fprintd::verify(&f.client, USER, Duration::from_secs(5), cancel).await;
    assert_eq!(r, UvResult::Cancelled);
    let calls = f.mock.calls();
    assert!(calls.claims.is_empty());
    assert_eq!(calls.releases, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout() {
    let f = fixture(MockFprintd::with_results(&["verify-retry-scan"], ms(10))).await;
    assert_eq!(verify(&f, ms(400)).await, UvResult::TimedOut);
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_enrolled_fingers() {
    let f = fixture(MockFprintd::default().without_enrolled()).await;
    assert_eq!(fprintd::has_enrolled(&f.client, USER).await, Ok(false));
    assert_eq!(f.mock.calls().list_enrolled, vec![USER.to_owned()]);

    // VerifyStart fails with NoEnrolledPrints; the claim is still released.
    assert!(matches!(
        verify(&f, Duration::from_secs(5)).await,
        UvResult::Unavailable(_)
    ));
    let calls = f.mock.calls();
    assert_eq!(calls.releases, 1);
    assert!(!f.mock.is_claimed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn has_enrolled_true() {
    let f = fixture(MockFprintd::default()).await;
    assert_eq!(fprintd::has_enrolled(&f.client, USER).await, Ok(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_fprintd_is_unavailable() {
    let bus = PrivateBus::start();
    let client = bus.connect().await;
    assert!(matches!(
        fprintd::verify(
            &client,
            USER,
            Duration::from_secs(5),
            CancellationToken::new()
        )
        .await,
        UvResult::Unavailable(_)
    ));
    assert!(fprintd::has_enrolled(&client, USER).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_busy_is_unavailable() {
    let f = fixture(MockFprintd::default()).await;
    // Another client holds the claim.
    let other = zbus::connection::Builder::address(f.bus_address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    other
        .call_method(
            Some(fprintd::SERVICE),
            DEVICE_PATH,
            Some(DEVICE_IFACE),
            "Claim",
            &("mallory",),
        )
        .await
        .unwrap();
    assert!(matches!(
        verify(&f, Duration::from_secs(5)).await,
        UvResult::Unavailable(_)
    ));
}

/// Emits a forged `VerifyStatus("verify-match", true)` from `spoofer` as soon as the scan
/// starts, both as a broadcast and unicast to the client.
async fn spoof_when_verifying(f: &Fixture, spoofer: Connection) -> tokio::task::JoinHandle<()> {
    let mock = f.mock.clone();
    let target = f.client.unique_name().unwrap().to_owned();
    tokio::spawn(async move {
        while !mock.is_verifying() {
            tokio::time::sleep(ms(5)).await;
        }
        for _ in 0..5 {
            spoofer
                .emit_signal(
                    None::<&str>,
                    DEVICE_PATH,
                    DEVICE_IFACE,
                    "VerifyStatus",
                    &("verify-match", true),
                )
                .await
                .unwrap();
            spoofer
                .emit_signal(
                    Some(target.as_str()),
                    DEVICE_PATH,
                    DEVICE_IFACE,
                    "VerifyStatus",
                    &("verify-match", true),
                )
                .await
                .unwrap();
            tokio::time::sleep(ms(20)).await;
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spoofed_match_from_non_owner_is_ignored_until_timeout() {
    let f = fixture(MockFprintd::with_results(&[], ms(10))).await;
    let spoofer = zbus::connection::Builder::address(f.bus_address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let task = spoof_when_verifying(&f, spoofer).await;
    assert_eq!(verify(&f, ms(600)).await, UvResult::TimedOut);
    task.await.unwrap();
    assert_cleaned_up(&f);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spoofed_match_does_not_override_real_no_match() {
    let f = fixture(MockFprintd::with_results(
        &["verify-retry-scan", "verify-no-match"],
        ms(150),
    ))
    .await;
    let spoofer = zbus::connection::Builder::address(f.bus_address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let task = spoof_when_verifying(&f, spoofer).await;
    assert_eq!(verify(&f, Duration::from_secs(5)).await, UvResult::NoMatch);
    task.await.unwrap();
    assert_cleaned_up(&f);
}

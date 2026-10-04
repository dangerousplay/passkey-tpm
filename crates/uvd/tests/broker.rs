//! Broker end to end on a private bus: swtpm + mock fprintd + broker + client.

use std::time::Duration;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use passkey_tpm_testkit::bus::PrivateBus;
use passkey_tpm_testkit::swtpm::Swtpm;
use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_uv::mock::{self, MockFprintd};
use passkey_tpm_uvd::{serve, Broker, SessionPolicy, TpmWorker, UserLookup, BUS_NAME, OBJECT_PATH};
use passkey_tpm_wire::cbor::{self, Value};
use sha2::{Digest, Sha256};
use tss_esapi::Context;
use zbus::Connection;

struct AlwaysAlice;
impl UserLookup for AlwaysAlice {
    fn username(&self, _uid: u32) -> Option<String> {
        Some("alice".to_owned())
    }
}

/// Session policy with a fixed answer (the logind client has its own tests).
struct Seat(bool);
impl SessionPolicy for Seat {
    fn is_active<'a>(
        &'a self,
        _uid: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(std::future::ready(self.0))
    }
}

struct Fixture {
    _tpm: Swtpm,
    _bus: PrivateBus,
    _broker: Connection,
    _fprintd: Connection,
    client: Connection,
    state: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

fn suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

async fn fixture(mock_fprintd: MockFprintd) -> Fixture {
    fixture_at_seat(mock_fprintd, true).await
}

async fn fixture_at_seat(mock_fprintd: MockFprintd, active: bool) -> Fixture {
    let tpm = Swtpm::start();
    let bus = PrivateBus::start();
    let fprintd = bus.connect().await;
    mock::serve(&fprintd, mock_fprintd)
        .await
        .expect("mock fprintd");
    let broker_conn = bus.connect().await;
    let state = std::env::temp_dir().join(format!(
        "passkey-tpm-uvd-test-{}-{}",
        std::process::id(),
        suffix()
    ));
    let tcti = tpm.tcti();
    let dir = state.clone();
    let worker = TpmWorker::spawn(move || TpmBackend::new(Context::new(tcti).expect("tpm"), dir))
        .expect("worker");
    let broker = Broker::new(
        worker,
        broker_conn.clone(),
        Box::new(AlwaysAlice),
        Box::new(Seat(active)),
        Duration::from_secs(5),
    );
    serve(&broker_conn, broker).await.expect("serve broker");
    let client = bus.connect().await;
    Fixture {
        _tpm: tpm,
        _bus: bus,
        _broker: broker_conn,
        _fprintd: fprintd,
        client,
        state,
    }
}

async fn ctap(client: &Connection, request: &[u8]) -> Vec<u8> {
    let reply = client
        .call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "Ctap",
            &(request.to_vec(),),
        )
        .await
        .expect("Ctap call");
    reply.body().deserialize::<Vec<u8>>().expect("reply body")
}

fn int(i: i64) -> Value {
    Value::int_key(i)
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn make_credential_request(rp: &str, cdh: &[u8; 32]) -> Vec<u8> {
    let mut r = vec![0x01];
    r.extend(cbor::encode(&Value::Map(vec![
        (int(1), Value::Bytes(cdh.to_vec())),
        (int(2), Value::Map(vec![(text("id"), text(rp))])),
        (
            int(3),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![1; 16])),
                (text("name"), text("alice")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), int(-7)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (int(7), Value::Map(vec![(text("uv"), Value::Bool(true))])),
    ])));
    r
}

fn get_assertion_request(rp: &str, cdh: &[u8; 32], cred_id: &[u8]) -> Vec<u8> {
    let mut r = vec![0x02];
    r.extend(cbor::encode(&Value::Map(vec![
        (int(1), text(rp)),
        (int(2), Value::Bytes(cdh.to_vec())),
        (
            int(3),
            Value::Array(vec![Value::Map(vec![
                (text("id"), Value::Bytes(cred_id.to_vec())),
                (text("type"), text("public-key")),
            ])]),
        ),
    ])));
    r
}

fn body(resp: &[u8]) -> Value {
    assert_eq!(resp[0], 0x00, "CTAP status {:#04x}", resp[0]);
    cbor::decode(&resp[1..]).expect("response CBOR")
}

fn verify(key: &VerifyingKey, signed: &[u8], cdh: &[u8; 32], der: &[u8]) {
    let digest = sha256(&[signed, cdh]);
    key.verify_prehash(&digest, &Signature::from_der(der).expect("DER"))
        .expect("signature");
}

#[tokio::test(flavor = "multi_thread")]
async fn register_then_sign_in_with_fingerprint() {
    let f = fixture(MockFprintd::with_results(
        &["verify-match"],
        Duration::from_millis(10),
    ))
    .await;
    let rp = "webauthn.io";

    let info = body(&ctap(&f.client, &[0x04]).await);
    assert_eq!(
        info.map_get(&int(4)).and_then(|o| o.map_get(&text("uv"))),
        Some(&Value::Bool(true))
    );

    let cdh = [0x11; 32];
    let resp = body(&ctap(&f.client, &make_credential_request(rp, &cdh)).await);
    let auth = resp
        .map_get(&int(2))
        .and_then(Value::as_bytes)
        .expect("authData")
        .to_vec();
    assert_eq!(&auth[..32], &sha256(&[rp.as_bytes()]));
    assert_eq!(auth[32], 0x45, "UP | UV | AT");
    let id_len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    let cred_id = auth[55..55 + id_len].to_vec();
    let cose = cbor::decode(&auth[55 + id_len..]).expect("COSE key");
    let x = cose.map_get(&int(-2)).and_then(Value::as_bytes).expect("x");
    let y = cose.map_get(&int(-3)).and_then(Value::as_bytes).expect("y");
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let key = VerifyingKey::from_sec1_bytes(&sec1).expect("P-256 key");
    let att = resp.map_get(&int(3)).expect("attStmt");
    let att_sig = att
        .map_get(&text("sig"))
        .and_then(Value::as_bytes)
        .expect("sig");
    verify(&key, &auth, &cdh, att_sig);

    let cdh2 = [0x22; 32];
    let resp = body(&ctap(&f.client, &get_assertion_request(rp, &cdh2, &cred_id)).await);
    let auth2 = resp
        .map_get(&int(2))
        .and_then(Value::as_bytes)
        .expect("authData");
    assert_eq!(auth2[32], 0x05, "UP | UV");
    let sig = resp
        .map_get(&int(3))
        .and_then(Value::as_bytes)
        .expect("signature");
    verify(&key, auth2, &cdh2, sig);

    // Same credential, other relying party: not found.
    assert_eq!(
        ctap(
            &f.client,
            &get_assertion_request("evil.example", &cdh2, &cred_id)
        )
        .await,
        vec![0x2E]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_aborts_the_fingerprint_prompt() {
    let f = fixture(MockFprintd::with_results(&[], Duration::from_millis(10))).await;
    let client = f.client.clone();
    let pending = tokio::spawn(async move {
        ctap(&client, &make_credential_request("a.example", &[1; 32])).await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    f.client
        .call_method(Some(BUS_NAME), OBJECT_PATH, Some(BUS_NAME), "Cancel", &())
        .await
        .expect("Cancel");
    let resp = tokio::time::timeout(Duration::from_secs(3), pending)
        .await
        .expect("finished")
        .expect("task");
    assert_eq!(resp, vec![0x2D], "CTAP2_ERR_KEEPALIVE_CANCEL");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_finger_is_denied() {
    let f = fixture(MockFprintd::with_results(
        &["verify-no-match"],
        Duration::from_millis(10),
    ))
    .await;
    assert_eq!(
        ctap(&f.client, &make_credential_request("a.example", &[1; 32])).await,
        vec![0x27]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn users_without_fingerprints_are_told_uv_is_unavailable() {
    let f = fixture(MockFprintd::default().without_enrolled()).await;
    let info = body(&ctap(&f.client, &[0x04]).await);
    assert_eq!(
        info.map_get(&int(4)).and_then(|o| o.map_get(&text("uv"))),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        ctap(&f.client, &make_credential_request("a.example", &[1; 32])).await,
        vec![0x30]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn user_without_an_active_seat_session_is_denied() {
    // HARD-01: after a user switch, another user can open this user's hidraw node; the
    // broker must not serve the (now background) user.
    let f = fixture_at_seat(
        MockFprintd::with_results(&[], Duration::from_millis(10)),
        false,
    )
    .await;
    let get_info = ctap(&f.client, &[0x04]).await;
    assert_eq!(get_info, vec![0x27], "CTAP2_ERR_OPERATION_DENIED");
    let cdh = [7u8; 32];
    let make = ctap(&f.client, &make_credential_request("example.com", &cdh)).await;
    assert_eq!(make, vec![0x27]);
}

//! passkey-tpm session agent: the CTAPHID side of the virtual security key.
//!
//! [`Hid`] is the pure protocol logic: channel allocation, reassembly (the verified
//! [`Assembler`]), busy handling, keepalives and the relay decision. The binary connects it
//! to `/dev/uhid`, the broker on the system bus, and desktop notifications. The agent makes
//! no security decisions: the broker validates everything and the TPM enforces the policy.

use passkey_tpm_core::ctaphid::{
    error_report, fragment, init_response, keepalive_report, Action, Assembler, BROADCAST_CID,
    CMD_CANCEL, CMD_CBOR, CMD_ERROR, CMD_INIT, CMD_PING, CMD_WINK, ERR_CHANNEL_BUSY,
    ERR_INVALID_CHANNEL, ERR_INVALID_CMD, ERR_INVALID_LEN, ERR_INVALID_PAR, REPORT_LEN,
    STATUS_PROCESSING, STATUS_UPNEEDED,
};
use passkey_tpm_wire::cbor::{self, Value};

/// CTAPHID capability flags (CTAP 2.1 §11.2.9.1.3): WINK | CBOR | NMSG (no CTAP1/U2F).
pub const CAPABILITIES: u8 = 0x01 | 0x04 | 0x08;
/// How many allocated channels are remembered.
const MAX_CHANNELS: usize = 16;

/// Something the binary must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Write these input reports to the device.
    Write(Vec<[u8; REPORT_LEN]>),
    /// Send this CTAP request to the broker; feed the reply to [`Hid::on_broker_reply`].
    Broker(Vec<u8>),
    /// Ask the broker to cancel the pending fingerprint prompt.
    Cancel,
    /// Show a desktop notification asking for the fingerprint, naming the relying party.
    Prompt(String),
}

#[derive(Debug)]
struct InFlight {
    cid: u32,
    keepalive_status: u8,
}

/// CTAPHID session state.
#[derive(Debug)]
pub struct Hid<R: FnMut() -> u32> {
    assembler: Assembler,
    channels: Vec<u32>,
    in_flight: Option<InFlight>,
    random_cid: R,
}

/// Strips the report-ID byte the kernel prepends for devices without report IDs. Decided by
/// length, not content: a channel ID may legitimately start with 0x00.
fn normalise(data: &[u8]) -> Option<[u8; REPORT_LEN]> {
    let body = match data.len() {
        65 => data.get(1..)?,
        n if n <= REPORT_LEN => data,
        _ => return None,
    };
    let mut report = [0u8; REPORT_LEN];
    report.get_mut(..body.len())?.copy_from_slice(body);
    Some(report)
}

fn reports(cid: u32, cmd: u8, payload: &[u8]) -> Effect {
    Effect::Write(
        fragment(cid, cmd, payload).unwrap_or_else(|| vec![error_report(cid, ERR_INVALID_LEN)]),
    )
}

fn error(cid: u32, code: u8) -> Effect {
    Effect::Write(vec![error_report(cid, code)])
}

/// What to name in the fingerprint prompt for a request that needs a gesture, if any.
/// Informational only: the broker decides whether a gesture is needed.
#[must_use]
pub fn relying_party(request: &[u8]) -> Option<String> {
    let (&command, params) = request.split_first()?;
    let map = || cbor::decode(params).ok();
    match command {
        0x01 => map()?
            .map_get(&Value::Uint(2))?
            .map_get(&Value::Text("id".into()))?
            .as_text()
            .map(str::to_owned),
        0x02 => map()?
            .map_get(&Value::Uint(1))?
            .as_text()
            .map(str::to_owned),
        // clientPIN getPinUvAuthTokenUsingUvWithPermissions.
        0x06 => {
            let m = map()?;
            (m.map_get(&Value::Uint(2))?.as_uint()? == 6).then(|| {
                m.map_get(&Value::Uint(10))
                    .and_then(Value::as_text)
                    .map_or_else(|| "passkey-tpm".to_owned(), str::to_owned)
            })
        }
        0x07 => Some("reset passkey-tpm".to_owned()),
        0x0B => Some("select passkey-tpm".to_owned()),
        _ => None,
    }
}

impl<R: FnMut() -> u32> Hid<R> {
    /// `random_cid` must return uniformly random `u32`s (OS RNG in production).
    pub fn new(random_cid: R) -> Self {
        Self {
            assembler: Assembler::new(),
            channels: Vec::new(),
            in_flight: None,
            random_cid,
        }
    }

    fn allocate(&mut self) -> u32 {
        loop {
            let cid = (self.random_cid)();
            if cid != 0 && cid != BROADCAST_CID && !self.channels.contains(&cid) {
                if self.channels.len() >= MAX_CHANNELS {
                    self.channels.remove(0);
                }
                self.channels.push(cid);
                return cid;
            }
        }
    }

    /// Handles one OUTPUT report from the host.
    pub fn on_output(&mut self, data: &[u8], now_ms: u64) -> Vec<Effect> {
        let Some(report) = normalise(data) else {
            return Vec::new();
        };
        let mut effects = Vec::new();
        if let Action::Error { cid, code } = self.assembler.on_tick(now_ms) {
            effects.push(error(cid, code));
        }
        match self.assembler.on_report(&report, now_ms) {
            Action::None => {}
            Action::Error { cid, code } => effects.push(error(cid, code)),
            Action::Complete { cid, cmd, payload } => {
                effects.extend(self.on_message(cid, cmd, payload));
            }
        }
        effects
    }

    fn on_message(&mut self, cid: u32, cmd: u8, payload: Vec<u8>) -> Vec<Effect> {
        if cmd == CMD_INIT {
            let Ok(nonce) = <[u8; 8]>::try_from(payload.as_slice()) else {
                return vec![error(cid, ERR_INVALID_LEN)];
            };
            let new_cid = if cid == BROADCAST_CID {
                self.allocate()
            } else {
                cid
            };
            return vec![reports(
                cid,
                CMD_INIT,
                &init_response(&nonce, new_cid, CAPABILITIES),
            )];
        }
        if cid == BROADCAST_CID || !self.channels.contains(&cid) {
            return vec![error(cid, ERR_INVALID_CHANNEL)];
        }
        if let Some(busy) = &self.in_flight {
            return if busy.cid == cid && cmd == CMD_CANCEL {
                vec![Effect::Cancel]
            } else {
                vec![error(cid, ERR_CHANNEL_BUSY)]
            };
        }
        match cmd {
            CMD_PING => vec![reports(cid, CMD_PING, &payload)],
            CMD_WINK => vec![reports(cid, CMD_WINK, &[])],
            // CANCEL with nothing in flight is ignored (CTAP 2.1 §11.2.9.2.4).
            CMD_CANCEL => Vec::new(),
            CMD_CBOR => {
                if payload.is_empty() {
                    return vec![error(cid, ERR_INVALID_LEN)];
                }
                let prompt = relying_party(&payload);
                self.in_flight = Some(InFlight {
                    cid,
                    keepalive_status: if prompt.is_some() {
                        STATUS_UPNEEDED
                    } else {
                        STATUS_PROCESSING
                    },
                });
                let mut effects = Vec::new();
                if let Some(rp) = prompt {
                    effects.push(Effect::Prompt(rp));
                }
                effects.push(Effect::Broker(payload));
                effects
            }
            CMD_ERROR => vec![error(cid, ERR_INVALID_PAR)],
            _ => vec![error(cid, ERR_INVALID_CMD)],
        }
    }

    /// Periodic tick (every ~100 ms): reassembly timeouts and keepalives.
    pub fn on_tick(&mut self, now_ms: u64) -> Vec<Effect> {
        let mut effects = Vec::new();
        if let Action::Error { cid, code } = self.assembler.on_tick(now_ms) {
            effects.push(error(cid, code));
        }
        if let Some(busy) = &self.in_flight {
            effects.push(Effect::Write(vec![keepalive_report(
                busy.cid,
                busy.keepalive_status,
            )]));
        }
        effects
    }

    /// The broker answered the in-flight request.
    pub fn on_broker_reply(&mut self, response: &[u8]) -> Vec<Effect> {
        match self.in_flight.take() {
            Some(busy) => vec![reports(busy.cid, CMD_CBOR, response)],
            None => Vec::new(),
        }
    }

    /// True while a CBOR request is waiting for the broker.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.in_flight.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_packet(cid: u32, cmd: u8, payload: &[u8]) -> Vec<u8> {
        fragment(cid, cmd, payload).unwrap().remove(0).to_vec()
    }

    fn hid() -> Hid<impl FnMut() -> u32> {
        let mut next = 0x0000_1233u32;
        Hid::new(move || {
            next += 1;
            next
        })
    }

    fn open_channel(h: &mut Hid<impl FnMut() -> u32>) -> u32 {
        let effects = h.on_output(
            &init_packet(BROADCAST_CID, CMD_INIT, &[1, 2, 3, 4, 5, 6, 7, 8]),
            0,
        );
        let Effect::Write(r) = &effects[0] else {
            panic!("{effects:?}")
        };
        assert_eq!(&r[0][7..15], &[1, 2, 3, 4, 5, 6, 7, 8], "nonce echoed");
        u32::from_be_bytes(r[0][15..19].try_into().unwrap())
    }

    #[test]
    fn init_allocates_a_channel_and_ping_echoes() {
        let mut h = hid();
        let cid = open_channel(&mut h);
        assert_eq!(cid, 0x1234);
        let effects = h.on_output(&init_packet(cid, CMD_PING, b"hello"), 1);
        assert_eq!(effects, vec![reports(cid, CMD_PING, b"hello")]);
    }

    #[test]
    fn report_id_prefix_is_stripped_only_for_65_byte_reports() {
        let mut h = hid();
        let cid = open_channel(&mut h);
        let mut prefixed = vec![0u8];
        prefixed.extend(init_packet(cid, CMD_PING, b"x"));
        assert_eq!(
            h.on_output(&prefixed, 1),
            vec![reports(cid, CMD_PING, b"x")]
        );
        // A 64-byte report whose CID starts with 0x00 must be left intact.
        assert_eq!(cid >> 24, 0);
        assert_eq!(
            h.on_output(&init_packet(cid, CMD_PING, b"y"), 2),
            vec![reports(cid, CMD_PING, b"y")]
        );
    }

    #[test]
    fn unknown_channels_are_rejected() {
        let mut h = hid();
        let effects = h.on_output(&init_packet(0xdead_beef, CMD_PING, b"x"), 0);
        assert_eq!(effects, vec![error(0xdead_beef, ERR_INVALID_CHANNEL)]);
    }

    #[test]
    fn cbor_request_is_relayed_with_prompt_keepalive_and_cancel() {
        let mut h = hid();
        let cid = open_channel(&mut h);
        let mut req = vec![0x02];
        req.extend(cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Text("example.com".into())),
            (Value::Uint(2), Value::Bytes(vec![0; 32])),
        ])));
        let effects = h.on_output(&init_packet(cid, CMD_CBOR, &req), 0);
        assert_eq!(
            effects,
            vec![Effect::Prompt("example.com".into()), Effect::Broker(req)]
        );
        assert!(h.is_busy());
        assert_eq!(
            h.on_tick(100),
            vec![Effect::Write(vec![keepalive_report(cid, STATUS_UPNEEDED)])]
        );
        let other = open_channel(&mut h);
        assert_eq!(
            h.on_output(&init_packet(other, CMD_PING, b"x"), 150),
            vec![error(other, ERR_CHANNEL_BUSY)]
        );
        assert_eq!(
            h.on_output(&init_packet(cid, CMD_CANCEL, &[]), 200),
            vec![Effect::Cancel]
        );
        assert_eq!(
            h.on_broker_reply(&[0x2d]),
            vec![reports(cid, CMD_CBOR, &[0x2d])]
        );
        assert!(!h.is_busy());
        assert!(h.on_tick(300).is_empty());
    }

    #[test]
    fn get_info_uses_processing_keepalive_and_no_prompt() {
        let mut h = hid();
        let cid = open_channel(&mut h);
        assert_eq!(
            h.on_output(&init_packet(cid, CMD_CBOR, &[0x04]), 0),
            vec![Effect::Broker(vec![0x04])]
        );
        assert_eq!(
            h.on_tick(100),
            vec![Effect::Write(vec![keepalive_report(
                cid,
                STATUS_PROCESSING
            )])]
        );
    }

    #[test]
    fn relying_party_extraction() {
        let mut mc = vec![0x01];
        mc.extend(cbor::encode(&Value::Map(vec![(
            Value::Uint(2),
            Value::Map(vec![(
                Value::Text("id".into()),
                Value::Text("rp.test".into()),
            )]),
        )])));
        assert_eq!(relying_party(&mc).as_deref(), Some("rp.test"));
        assert_eq!(relying_party(&[0x04]), None);
        assert_eq!(relying_party(&[0x07]).as_deref(), Some("reset passkey-tpm"));
        let mut uv_token = vec![0x06];
        uv_token.extend(cbor::encode(&Value::Map(vec![
            (Value::Uint(2), Value::Uint(6)),
            (Value::Uint(10), Value::Text("rp.test".into())),
        ])));
        assert_eq!(relying_party(&uv_token).as_deref(), Some("rp.test"));
        let mut retries = vec![0x06];
        retries.extend(cbor::encode(&Value::Map(vec![(
            Value::Uint(2),
            Value::Uint(1),
        )])));
        assert_eq!(
            relying_party(&retries),
            None,
            "getPINRetries needs no gesture"
        );
        assert_eq!(relying_party(&[0x02, 0xff]), None);
    }
}

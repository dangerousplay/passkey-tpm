//! authenticatorGetInfo (CTAP 2.1 §6.4, M2-01).

use passkey_tpm_wire::cbor::Value;

use super::common::{
    int, ok, text, AAGUID, ES256, MAX_CREDENTIAL_COUNT_IN_LIST, MAX_CREDENTIAL_ID_LENGTH,
    MAX_MSG_SIZE, MIN_PIN_LENGTH,
};

/// Facts about the user the response depends on.
#[derive(Debug, Clone, Copy)]
pub struct InfoFacts {
    pub uv_enrolled: bool,
    pub pin_set: bool,
    pub remaining_resident: usize,
}

pub fn get_info(f: InfoFacts) -> Vec<u8> {
    let count = |n: usize| Value::Uint(u64::try_from(n).unwrap_or(u64::MAX));
    ok(&Value::Map(vec![
        (
            int(0x01),
            Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]),
        ),
        (
            int(0x02),
            Value::Array(vec![text("credProtect"), text("hmac-secret")]),
        ),
        (int(0x03), Value::Bytes(AAGUID.to_vec())),
        (
            int(0x04),
            Value::Map(vec![
                (text("rk"), Value::Bool(true)),
                (text("up"), Value::Bool(true)),
                (text("uv"), Value::Bool(f.uv_enrolled)),
                (text("plat"), Value::Bool(false)),
                (text("credMgmt"), Value::Bool(true)),
                (text("clientPin"), Value::Bool(f.pin_set)),
                (text("pinUvAuthToken"), Value::Bool(true)),
                (text("makeCredUvNotRqd"), Value::Bool(false)),
            ]),
        ),
        (int(0x05), Value::Uint(MAX_MSG_SIZE)),
        (
            int(0x06),
            Value::Array(vec![Value::Uint(2), Value::Uint(1)]),
        ),
        (int(0x07), count(MAX_CREDENTIAL_COUNT_IN_LIST)),
        (int(0x08), Value::Uint(MAX_CREDENTIAL_ID_LENGTH)),
        (int(0x09), Value::Array(vec![text("usb")])),
        (
            int(0x0A),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), int(ES256)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (int(0x0D), count(MIN_PIN_LENGTH)),
        (int(0x0E), Value::Uint(0x0002_0000)),
        (int(0x14), count(f.remaining_resident)),
    ]))
}

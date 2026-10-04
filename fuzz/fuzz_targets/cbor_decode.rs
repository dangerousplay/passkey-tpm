#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_wire::cbor::{decode, encode, map_value_raw, Value};

fuzz_target!(|data: &[u8]| {
    // Never panics. Anything accepted re-encodes canonically to bytes that decode again,
    // the canonical encoding is a fixed point, and canonical input round-trips exactly.
    // (Decoding is liberal about map key order, so non-canonical input may come back with
    // its map entries reordered.)
    // map_value_raw never panics, fails exactly when decode does, and returns a sub-slice
    // that is itself one valid item.
    for key in 0..4 {
        match map_value_raw(data, &Value::Uint(key)) {
            Ok(Some(raw)) => assert!(decode(raw).is_ok(), "raw value span does not decode"),
            Ok(None) => assert!(decode(data).is_ok()),
            Err(e) => assert_eq!(decode(data).err(), Some(e)),
        }
    }
    if let Ok(value) = decode(data) {
        let canonical = encode(&value);
        let again = decode(&canonical);
        assert!(again.is_ok(), "canonical re-encoding rejected: {again:?}");
        if let Ok(v) = again {
            assert_eq!(encode(&v), canonical);
            if canonical == data {
                assert_eq!(v, value);
            }
        }
    }
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_wire::cbor::{decode, encode};

fuzz_target!(|data: &[u8]| {
    // Never panics. Anything accepted re-encodes canonically to bytes that decode again,
    // the canonical encoding is a fixed point, and canonical input round-trips exactly.
    // (Decoding is liberal about map key order, so non-canonical input may come back with
    // its map entries reordered.)
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

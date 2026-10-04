#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_wire::reader::Reader;

// Same property as the Kani harnesses, on unbounded inputs: walking a chain of
// TPM2B-style fields never panics and never reads past the end.
fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    while let Ok(body) = r.len16_prefixed() {
        assert!(body.len() <= data.len());
    }
    while r.u8().is_ok() {}
    assert!(r.is_empty());
});

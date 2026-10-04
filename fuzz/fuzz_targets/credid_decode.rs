#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_wire::credid::CredBlobs;

fuzz_target!(|data: &[u8]| {
    // Never panics; anything accepted re-encodes to exactly the same bytes (canonical form).
    if let Ok(blobs) = CredBlobs::decode(data) {
        assert_eq!(blobs.encode().as_deref(), Ok(data));
    }
});

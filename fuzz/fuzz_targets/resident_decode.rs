#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_wire::resident;

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = resident::decode(data) {
        // The encoding is canonical: re-encoding gives the input back, which decodes the same.
        let bytes = resident::encode(&entries);
        assert_eq!(bytes.as_deref(), Ok(data));
        assert_eq!(resident::decode(data), Ok(entries));
    }
});

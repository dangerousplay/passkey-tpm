#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_wire::gatestore::GateStore;

fuzz_target!(|data: &[u8]| {
    if let Ok(store) = GateStore::decode(data) {
        assert_eq!(store.encode().as_deref().map(Vec::as_slice), Ok(data));
    }
});

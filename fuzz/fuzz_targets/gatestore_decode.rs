#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_wire::gatestore::{GateStore, VERSION_PENDING_PIN};

fuzz_target!(|data: &[u8]| {
    if let Ok(store) = GateStore::decode(data) {
        // Version 2 exactly when a PIN change is pending; both versions round-trip.
        assert_eq!(store.pending_pin.is_some(), data[4] == VERSION_PENDING_PIN);
        assert_eq!(store.encode().as_deref().map(Vec::as_slice), Ok(data));
    }
});

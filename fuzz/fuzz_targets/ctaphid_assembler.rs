#![no_main]

use libfuzzer_sys::fuzz_target;
use passkey_tpm_core::ctaphid::{Action, Assembler, MAX_MSG, REPORT_LEN};

// Arbitrary report streams never panic the assembler and never yield an oversized
// message. Each 64-byte chunk is one report (the last one zero padded); the first
// byte of the input drives a monotonic fake clock so timeouts get exercised too.
fuzz_target!(|data: &[u8]| {
    let Some((&step, reports)) = data.split_first() else {
        return;
    };
    let mut a = Assembler::new();
    let mut now: u64 = 0;
    for chunk in reports.chunks(REPORT_LEN) {
        let mut report = [0u8; REPORT_LEN];
        report[..chunk.len()].copy_from_slice(chunk);
        now = now.saturating_add(u64::from(step) * 8);
        for action in [a.on_tick(now), a.on_report(&report, now)] {
            if let Action::Complete { payload, .. } = action {
                assert!(payload.len() <= MAX_MSG);
            }
        }
    }
});

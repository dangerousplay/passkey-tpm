# MVP-1 Authenticator — Tasks

**Design:** `design.md` · **Testing:** `.specs/codebase/TESTING.md` · **Status:** Done (real-fprintd E2E pending)

## Results

| Task | Status | Notes |
|---|---|---|
| T1 | ✅ | scan (no alloc, all rejection rules) + build; Kani: scan panic-free ≤ 8 B, head/arg/UTF-8 helpers; `build` loop not Kani-proven (CBMC blow-up on recursive drop) → proptest + 7M fuzz runs. Decoder accepts non-canonical key order (liberal), encoder canonical |
| T2 | ✅ | Verus: 53 new obligations (66 total then), no trusted items; 7.6M fuzz runs |
| T3 | ✅ | 17 tests; spoofed `VerifyStatus` (broadcast and unicast) ignored, proven by removing the check; calls bound to fprintd's unique name |
| T4 | ✅ | 13 tests, std-only, no `unsafe`; layout checked against `uhid.h`; privileged test not run (no /dev/uhid access) |
| T5 | ✅ | `systemd-analyze security`: 0.6 SAFE for the broker unit |
| T6 | ✅ | credid v2 = body ‖ 16-byte tag; `cred_mac_key` in gates.v1 |
| T7 | ✅ | `evidence.rs`: UV/UP/AT flag proofs (bit_vector), evidence ⇒ UV gate; 76 verified |
| T8 | ✅ | 11 tests incl. never-panics proptest; packed self-attestation, zero AAGUID |
| T9 | ✅ | `TpmBackend`; NV indexes allocated (authd-sized uids), restart-safe, 0700 per-user dirs |
| T10 | ✅ | Broker on private bus + swtpm + mock fprintd: register → assert with signatures verified, cancel, no-match, not enrolled |
| T11 | ✅ (unit) | `Hid` logic 6 tests; report-ID prefix stripped by length (fixes a latent Go bug: CIDs starting with 0x00) |
| T12 | ✅ (mock fprintd) | `scripts/e2e-local.sh` on the AMD fTPM: libfido2 `fido2-token -I`, `fido2-cred -M/-V -v`, `fido2-assert -G/-V -v` all pass. Real-fprintd run pending |


## Execution plan

```
Phase 1 (parallel, separate crates/files):
  T1 [P] wire::cbor                      (wire)
  T2 [P] core::ctaphid packets+assembler (core, Verus)
  T3 [P] uv: fprintd client + mock       (uv)
  T4 [P] transport-uhid device           (transport-uhid)
  T5 [P] packaging files                 (packaging/)

Phase 2 (sequential):
  T1 → T6 credid v2 tag + gatestore K_uid (wire, tpm)
  T2, T6 → T7 core::evidence + auth_data (core, Verus)
  T1, T7 → T8 core::ctap2 getInfo/makeCredential/getAssertion (core)
  T6 → T9 tpm::adapter TpmBackend (tpm)

Phase 3:
  T3, T8, T9 → T10 uvd broker + integration test (swtpm + mock fprintd + private bus)
  T2, T4, T10 → T11 agent (uhid + assembler + keepalive + notify)
  T11 → T12 end-to-end with fido2-token (privileged/manual)
```

## Tasks

| ID | What | Where | Req | Tests | Gate |
|---|---|---|---|---|---|
| T1 | CTAP2 CBOR subset decoder/encoder, canonical encoding, limits; Kani panic-freedom; fuzz target `cbor_decode` (decode→encode round-trip on canonical input) | `crates/passkey-tpm-wire/src/cbor.rs`, `fuzz/fuzz_targets/cbor_decode.rs` | MVP1-07, -13 | unit + bounded proof + fuzz | quick + proof |
| T2 | CTAPHID report parsing, Assembler state machine with Verus invariants, fragmentation; fuzz target `ctaphid_assembler` | `crates/passkey-tpm-core/src/ctaphid.rs`, `fuzz/fuzz_targets/ctaphid_assembler.rs` | MVP1-08, -13 | unit + proof + fuzz | quick + proof |
| T3 | fprintd client (`verify`, `has_enrolled`) with sender check and cancel; mock fprintd service (feature `mock`); tests on a private dbus-daemon | `crates/passkey-tpm-uv/` | MVP1-10 | integration-dbus | quick |
| T4 | uhid device: create/destroy, event decode, input write, no `unsafe`; FIDO report descriptor | `crates/passkey-tpm-transport-uhid/` | MVP1-11 | unit (encoding) + ignored privileged test | quick |
| T5 | systemd units, D-Bus policy, polkit rule, udev rule, sysusers/tmpfiles | `packaging/` | MVP1-12 | none | build |
| T6 | credid v2 with 16-byte tag; gatestore `cred_mac_key`; tag compute/verify helpers | `wire/credid.rs`, `wire/gatestore.rs`, `tpm/gates.rs` | MVP1-03 | unit + bounded proof + fuzz | quick + proof |
| T7 | `UvEvidence` + `auth_data` with Verus ensures on flags | `core/src/evidence.rs` | MVP1-05 | unit + proof | quick + proof |
| T8 | `Authenticator` two-phase API; getInfo, makeCredential, getAssertion; packed self-attestation; `MockTpm` | `core/src/ctap2/` | MVP1-01..06 | unit | quick |
| T9 | `TpmBackend: TpmOps` with lazy per-uid provisioning and persistence | `tpm/src/adapter.rs` | MVP1-09 | integration-tpm | quick |
| T10 | Broker service + integration test (register → assert, wrong uid, cancel) | `crates/passkey-tpm-uvd/` | MVP1-09, -10 | integration-dbus + tpm | full |
| T11 | Agent | `crates/passkey-tpm-agent/` | MVP1-08, -11 | unit + ignored privileged | quick |
| T12 | E2E script + docs/compat.md row | `scripts/e2e-fido2.sh`, `docs/` | acceptance | hardware/manual | — |

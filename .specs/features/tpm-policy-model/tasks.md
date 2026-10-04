# TPM Policy Model — Tasks

**Spec:** `.specs/features/tpm-policy-model/spec.md`
**Design:** `.specs/features/tpm-policy-model/design.md` (ADR-003, Accepted)
**Testing:** `.specs/codebase/TESTING.md`
**Status:** Done (library); CLI `tpm status` and the hardware benchmark are pending

## Results

| Task | Status | Notes |
|---|---|---|
| T0 | ✅ | Spec citations recorded in research.md; AD-010 |
| T1 | ✅ | `gates.rs` verified (13 obligations total in core). `MockTpm` deferred to the verified-core feature (first caller) |
| T2 | ✅ | In `passkey-tpm-wire` (AD-008). Kani bound N=14 (not 1100); proptest + fuzz cover longer inputs |
| T3 | ✅ | `wire::gatestore` + `tpm::fsutil::write_atomic` |
| T4 | ✅ | TCP swtpm (tss-esapi 7.7 TCTI parser has no unix-socket support); 8 parallel instances OK |
| T5 | ✅ | `tpm::policy` (moved from core: needs sha2, only the TPM shell uses it). KAT vs swtpm caught a wrong `TPM_CC_NV_ChangeAuth` (L-005) |
| T6 | ✅ | Ensure/open/pinned; foreign key at 0x81000001 rejected |
| T7 | ✅ (replaced) | `pin_gate` via NV undefine+redefine instead of FFI (AD-011); PolicySecret KAT included |
| T8 | ✅ | `session::with_policy` / `with_hmac`: salted, AES-128-CFB both ways; no leak in 200 iterations |
| T9 | ✅ | Found a gap: the PIN gate needs a random **bootstrap** authValue until the first setPIN (a known value would let any `tss` member satisfy the PIN branch); `gates.v1` extended |
| T10 | ✅ | authPolicy == software digest; `userWithAuth` clear. **Measured credential ID: 736 B with hmac-secret keys** (≤ 1023, above the ~700 B comfort level; advertise maxMsgSize ≥ 2048) |
| T11 | ✅ | Bypass tests assert the exact TPM reason: TPM-03 `TPM_RC_AUTH_UNAVAILABLE`; TPM-05/06/12 "policy check failed"; wrong PIN = authorization failure |
| T12 | ✅ | Deterministic; PIN and UV select the same WithUV key; WithoutUV differs; bound to user and RP |
| T13 | ✅ | Argon2id (19 MiB, t=2, p=1); regression vector cross-checked with the reference C `argon2` CLI |
| T14 | ✅ | `TPM2_Clear` → `TpmError::Reset`, no panic; `Error::to_tpm_error` classification |
| T15 | ✅ (lib) | `health::da_status` bypasses tss-esapi's permanent property cache (it would report stale lockout counters). CLI `tpm status` moves to the CLI feature |
| T16 | ✅ (swtpm) | `cargo xtask bench-tpm [--device]`. swtpm: ~15 ms p50 per op (not representative). **Hardware run pending:** the user isn't in the `tss` group |

**Prerequisite:** repo-bootstrap T1–T8 done (xtask gates exist)

---

## Execution Plan

### Phase 0: Spec checks (parallel with Phase 1)

```
T0 [P]
```

### Phase 1: Pure foundations (parallel)

```
┌→ T1 [P]  types + TpmOps trait (core)
├→ T2 [P]  credential ID codec (core)
├→ T3 [P]  gate-store file codec (core)
└→ T4 [P]  swtpm test harness (tpm crate)
```

### Phase 2: Pure policy math + TPM primitives

```
T1 ──→ T5 [P]  policy digest calculator
T4 ──→ T6 [P]  SRK provisioning + Name pinning
T4 ──→ T7 [P]  ffi.rs (NV_ChangeAuth, DA)
T6 ──→ T8      salted policy session helper
```

### Phase 3: Gates and credentials (sequential)

```
T3, T7, T8 ──→ T9   per-user gate provisioning
T2, T5, T9 ──→ T10  create_credential
T10 ──→ T11 sign (+ bypass tests)
T10 ──→ T12 hmac-secret
```

### Phase 4: Lifecycle (parallel after T11)

```
T11 ──→ T13 [P] change_pin
T11 ──→ T14 [P] health / reset detection
T7, T11 ─→ T15 [P] DA status + warning
T11, T12 → T16 [P] benchmark task
```

---

## Task Breakdown

### T0: Verify CTAP spec citations [P]

**What:** Confirm, from the CTAP 2.1/2.2 spec text, (a) the PIN token input is `LEFT(SHA-256(PIN),16)`; (b) CredRandomWithUV/WithoutUV semantics and 32-byte size; (c) the signCount=0 semantics in WebAuthn L3; (d) the credential ID max length. Record section numbers in `research.md`.
**Where:** `.specs/features/tpm-policy-model/research.md`
**Depends on:** None
**Requirement:** TPM-07, TPM-08, TPM-13, TPM-16
**Done when:** [ ] each item has a spec section citation or is flagged as a design change
**Tests:** none (docs) · **Gate:** none

---

### T1: Core TPM-facing types and `TpmOps` trait [P]

**What:** `GateKind {Pin, Uv, Up}`, `CredProtect`, `CredBlobs`, `Uid(u32)`, `RpIdHash([u8;32])`, `TpmError`, and the `TpmOps` trait (`create_credential`, `sign`, `hmac`, `change_pin`, `health`) as in design.md; a `MockTpm` for core tests.
**Where:** `crates/passkey-tpm-core/src/tpm_iface.rs`
**Depends on:** None
**Requirement:** TPM-02, TPM-05, TPM-07
**Done when:**
- [ ] The trait compiles without `unsafe`; `MockTpm` passes 3+ unit tests (gate/kind mismatch rejected, uid recorded)
- [ ] Gate passes: quick
**Tests:** unit · **Gate:** quick
**Commit:** `feat(core): TPM interface types and TpmOps trait`

---

### T2: Credential ID v1 codec [P]

**What:** `encode(&CredBlobs) -> Vec<u8>` / `decode(&[u8]) -> Result<CredBlobs>` per the design data model; reject trailing bytes, an unknown version and oversize input; ≤ 1023 B.
**Where:** `crates/passkey-tpm-wire/src/credid.rs`, `fuzz/fuzz_targets/credid_decode.rs`
**Depends on:** None
**Requirement:** TPM-01, TPM-16
**Done when:**
- [ ] proptest round-trip; Kani harness proves `decode` panic-free for inputs ≤ 1100 B; fuzz target registered
- [ ] Gate passes: quick + proof
**Tests:** unit + bounded proof + fuzz · **Gate:** quick + proof
**Commit:** `feat(core): credential ID v1 codec with Kani proof`

---

### T3: Gate-store file codec (`gates.v1`) [P]

**What:** Serialize/deserialize per-user gate state (UV/UP blobs + authValues, PIN NV handle, Argon2 salt, schema version); `Zeroizing` buffers for authValues; atomic write helper (temp + fsync + rename, 0600).
**Where:** `crates/passkey-tpm-wire/src/gatestore.rs` (codec, pure), `crates/passkey-tpm-tpm/src/fsutil.rs` (atomic write)
**Depends on:** None
**Requirement:** TPM-04, TPM-05, TPM-08
**Done when:**
- [ ] Round-trip proptest; Kani panic-freedom on decode; a corrupt file returns an error (never treated as empty)
- [ ] The atomic-write unit test (tempdir) leaves no partial file on a simulated failure
**Tests:** unit + bounded proof + fuzz · **Gate:** quick + proof
**Commit:** `feat(core): gates.v1 store codec and atomic writes`

---

### T4: swtpm test harness [P]

**What:** Test helper that spawns `swtpm socket --tpm2` on a temp dir with free ports, runs startup, returns a `tss_esapi::Context` (TCTI `swtpm:`), and kills it on drop; `xtask test` checks for the `swtpm` binary and fails with an install hint.
**Where:** `crates/passkey-tpm-tpm/tests/support/swtpm.rs`, `xtask/src/tasks/test.rs` (modify)
**Depends on:** None
**Requirement:** (enables all integration-tpm tests)
**Done when:**
- [ ] A smoke integration test gets 32 random bytes from `get_random`; 8 parallel tests don't collide
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `test(tpm): per-test swtpm harness`

---

### T5: Software policy digest calculator [P]

**What:** Pure functions: `policy_command_code(digest, cc)`, `policy_secret(digest, gate_name, policy_ref)`, `policy_or(branches)`, `policy_ref(tag, rp_id_hash)`, `credential_policy(gates, rp_id_hash, protect, cc)` (drops the UP branch for credProtect=3).
**Where:** `crates/passkey-tpm-core/src/policy.rs`
**Depends on:** T1
**Requirement:** TPM-02, TPM-06, TPM-12
**Done when:**
- [ ] Known-answer vectors (produced with `tpm2_policy*` trial sessions, committed as fixtures) match; unit tests for the credProtect=3 branch omission
**Tests:** unit · **Gate:** quick
**Commit:** `feat(core): software TPM policy digest calculator`

---

### T6: SRK provisioning + Name pinning [P]

**What:** `srk::ensure(ctx) -> SrkInfo`: read 0x81000001; if absent, `create_primary` with the TCG ECC P-256 SRK template and `evict_control`; return its Name. `srk::check(ctx, pinned_name)`.
**Where:** `crates/passkey-tpm-tpm/src/srk.rs`
**Depends on:** T4
**Requirement:** TPM-11
**Done when:**
- [ ] Integration tests: a fresh swtpm provisions the SRK; a second call reuses it (same Name); a spoofed different key at the handle is detected as a mismatch
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm): SRK provisioning and name pinning`

---

### T7: Minimal sys FFI: `NV_ChangeAuth`, DA parameters/status [P]

**What:** Safe wrappers over `tss-esapi-sys` for `Esys_NV_ChangeAuth`, `Esys_DictionaryAttackParameters`, and the TPM_PT_PERMANENT `lockoutAuthSet` read (via `get_capability` if available in the safe API). The only `unsafe` in the crate, with `// SAFETY:` comments.
**Where:** `crates/passkey-tpm-tpm/src/ffi.rs`
**Depends on:** T4
**Requirement:** TPM-09, TPM-14
**Done when:**
- [ ] Integration tests on swtpm: NV index auth changed (old auth fails, new succeeds); DA params set and read back
- [ ] `cargo xtask clippy` passes with `unsafe` confined to this file (`#![deny(unsafe_code)]` elsewhere)
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm): audited FFI for NV_ChangeAuth and DA`

---

### T8: Salted parameter-encrypted policy session helper

**What:** `session::policy(ctx, srk) -> AuthSession` (salted on the SRK, AES-128-CFB, encrypt+decrypt attributes) and `session::hmac(...)` for gate auth; flush on drop.
**Where:** `crates/passkey-tpm-tpm/src/session.rs`
**Depends on:** T6
**Requirement:** TPM-10
**Done when:**
- [ ] Integration test: a session starts and its attributes read back with encrypt/decrypt set; no handle leak after 100 iterations (`get_capability` handles count)
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm): salted encrypted policy sessions`

---

### T9: Per-user gate provisioning

**What:** `gates::provision(ctx, uid) -> GateSet`: UV and UP keyedHash objects (`noDA`, 32-byte random authValue), and a PIN NV index (DA-protected, authPolicy permitting `NV_ChangeAuth` only through PolicyCommandCode + PolicyAuthValue); persisted via the T3 codec to `<state>/<uid>/gates.v1`.
**Where:** `crates/passkey-tpm-tpm/src/gates.rs`
**Depends on:** T3, T7, T8
**Requirement:** TPM-04, TPM-05, TPM-08
**Done when:**
- [ ] Integration: two uids get distinct gate Names; reload from disk yields the same Names; `noDA` set on UV/UP and clear on the PIN gate (read_public / nv_read_public)
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm): per-user PIN/UV/UP gates`

---

### T10: `create_credential`

**What:** Create the cred key (ECC P-256, userWithAuth clear, adminWithPolicy, authPolicy from T5) and optional hmac_uv/hmac_nouv keyedHash keys (sign, unrestricted, HMAC-SHA256, policies on `TPM2_HMAC`); return `CredBlobs` → T2 codec.
**Where:** `crates/passkey-tpm-tpm/src/credential.rs`
**Depends on:** T2, T5, T9
**Requirement:** TPM-01, TPM-02, TPM-07, TPM-12, TPM-16
**Done when:**
- [ ] Integration: authPolicy in `read_public` equals the T5 software digest; userWithAuth clear; encoded ID ≤ 1023 B (size logged); no sensitive bytes in `CredBlobs` other than TPM2B_PRIVATE
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm): policy-bound credential creation`

---

### T11: `sign` with gate branch + bypass tests

**What:** The assertion flow from design.md (load, policy session, PolicyCommandCode, PolicySecret(gate[uid], policyRef), PolicyOR, Sign); `TpmOps::sign` impl.
**Where:** `crates/passkey-tpm-tpm/src/sign.rs`, `crates/passkey-tpm-tpm/tests/bypass.rs`
**Depends on:** T10
**Requirement:** TPM-02, TPM-03, TPM-05, TPM-06, TPM-12
**Done when:**
- [ ] The signature verifies with `p256` for each allowed branch
- [ ] **Negative tests pass:** (a) plain password session with empty auth → TPM_RC_AUTH_UNAVAILABLE / policy fail (TPM-03); (b) gate of uid B with a credential of uid A → fails (TPM-05); (c) correct gate, other rpIdHash → fails (TPM-06); (d) UP branch on a credProtect=3 credential → fails (TPM-12)
**Tests:** integration-tpm · **Gate:** full
**Commit:** `feat(tpm): gated signing with bypass regression tests`

---

### T12: hmac-secret via TPM2_HMAC

**What:** `TpmOps::hmac(uid, blobs, rp_id_hash, with_uv, gate, salt)`: policy session on `CommandCode::Hmac`; output through an encrypted session.
**Where:** `crates/passkey-tpm-tpm/src/hmac.rs`
**Depends on:** T10
**Requirement:** TPM-07
**Done when:**
- [ ] Integration: deterministic per (credential, salt); WithUV ≠ WithoutUV; different salt → different output; UP gate can't drive the WithUV key; 32-byte output
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm): TPM-held hmac-secret CredRandom`

---

### T13: `change_pin` [P]

**What:** Argon2id(pinHash16, salt) → `NV_ChangeAuth` on the PIN gate via T7.
**Where:** `crates/passkey-tpm-tpm/src/pin.rs`
**Depends on:** T11
**Requirement:** TPM-08, TPM-09
**Done when:**
- [ ] Integration (TPM-09): an existing credential signs with the new PIN; the old PIN fails; no credential blob changed
- [ ] Argon2 parameters documented; KDF known-answer unit test
**Tests:** integration-tpm + unit · **Gate:** quick
**Commit:** `feat(tpm): PIN change without credential invalidation`

---

### T14: Health and reset detection [P]

**What:** `TpmOps::health()`: SRK present + Name equals the pinned value → Ok; else `Reset`. Callers map it to CTAP errors (design error table).
**Where:** `crates/passkey-tpm-tpm/src/health.rs`
**Depends on:** T11
**Requirement:** TPM-15
**Done when:**
- [ ] Integration: `tpm2_clear` on swtpm → `Reset` reported and sign returns a typed error without panicking
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm): detect TPM clear / SRK loss`

---

### T15: DA status reporting and warning [P]

**What:** Read lockoutAuthSet and the DA params; `passkey-tpm-cli tpm status` prints them; warn when lockoutAuth is empty; `tpm set-da` admin-only command (no implicit changes).
**Where:** `crates/passkey-tpm-tpm/src/da.rs`, `crates/passkey-tpm-cli/src/tpm.rs`
**Depends on:** T7, T11
**Requirement:** TPM-14
**Done when:**
- [ ] Integration: fresh swtpm → warning shown; after setting lockoutAuth → no warning; no code path sets lockoutAuth except `set-da`
**Tests:** integration-tpm · **Gate:** quick
**Commit:** `feat(tpm,cli): dictionary-attack status and admin controls`

---

### T16: TPM benchmark task [P]

**What:** `cargo xtask bench-tpm [--device /dev/tpmrm0]`: N=50 register/sign/hmac runs reporting p50/p95; results template in `docs/compat.md`.
**Where:** `xtask/src/tasks/bench_tpm.rs`, `crates/passkey-tpm-tpm/benches/assert.rs`, `docs/compat.md`
**Depends on:** T11, T12
**Requirement:** TPM-17
**Done when:**
- [ ] Runs against swtpm in CI (smoke, no threshold); hardware results recorded for ≥1 machine (manual; AMD fTPM, Intel PTT and dTPM over time)
**Tests:** none (benchmark; gate = running it) · **Gate:** quick
**Commit:** `perf(tpm): assertion latency benchmark`

---

## Requirement traceability

| Req | Tasks | Notes |
|---|---|---|
| TPM-01 | T2, T10 | |
| TPM-02 | T1, T5, T10, T11 | |
| TPM-03 | T11 | negative test (a) |
| TPM-04 | T3, T9 | uid resolution from D-Bus credentials → **broker feature** |
| TPM-05 | T1, T9, T11 | negative test (b); uid source → broker feature |
| TPM-06 | T5, T11 | negative test (c) |
| TPM-07 | T0, T10, T12 | |
| TPM-08 | T0, T3, T9, T13 | |
| TPM-09 | T7, T13 | |
| TPM-10 | T8 | |
| TPM-11 | T6 | |
| TPM-12 | T5, T10, T11 | negative test (d) |
| TPM-13 | T0 | counter=0 is emitted by the core auth-data builder → **verified-core feature** |
| TPM-14 | T7, T15 | |
| TPM-15 | T14 | |
| TPM-16 | T0, T2, T10 | |
| TPM-17 | T16 | |

---

## Validation

### Granularity

| Task | Scope | Status |
|---|---|---|
| T0 | doc research | ✅ |
| T1 | one module (types + trait + mock) | ⚠️ cohesive |
| T2, T5, T6, T8–T14 | one module each | ✅ |
| T3 | codec (core) + atomic write helper (tpm) | ⚠️ 2 files, one concern (persisting gate state) |
| T4 | test harness + xtask check | ⚠️ 2 files, one concern |
| T7 | one FFI module | ✅ |
| T15 | lib module + CLI subcommand | ⚠️ 2 files, one concern |
| T16 | xtask task + bench + doc template | ⚠️ cohesive |

### Diagram–definition cross-check

| Task | Depends on (body) | Diagram | Status |
|---|---|---|---|
| T0 | — | — | ✅ |
| T1–T4 | — | — | ✅ |
| T5 | T1 | T1→T5 | ✅ |
| T6 | T4 | T4→T6 | ✅ |
| T7 | T4 | T4→T7 | ✅ |
| T8 | T6 | T6→T8 | ✅ |
| T9 | T3, T7, T8 | T3,T7,T8→T9 | ✅ |
| T10 | T2, T5, T9 | T2,T5,T9→T10 | ✅ |
| T11 | T10 | T10→T11 | ✅ |
| T12 | T10 | T10→T12 | ✅ |
| T13 | T11 | T11→T13 | ✅ |
| T14 | T11 | T11→T14 | ✅ |
| T15 | T7, T11 | T7,T11→T15 | ✅ |
| T16 | T11, T12 | T11,T12→T16 | ✅ |

T11 and T12 are both after T10 and independent, but neither is marked [P]: both add modules registered in `lib.rs`, so they run sequentially to avoid a conflict. That's optional; they can be parallelised if `lib.rs` is pre-declared in T10.

### Test co-location

| Task | Layer | Matrix requires | Task says | Status |
|---|---|---|---|---|
| T0 | docs | none | none | ✅ |
| T1 | core state/types | unit (+ proof when obligations exist; none in T1) | unit | ✅ |
| T2, T3 | parsers/codecs | unit + bounded proof + fuzz | same | ✅ |
| T4 | TPM shell (test support) | integration-tpm | integration-tpm | ✅ |
| T5 | pure policy helpers | unit (KAT) | unit | ✅ |
| T6–T12, T14, T15 | TPM shell | integration-tpm | integration-tpm | ✅ |
| T13 | TPM shell + KDF helper | integration-tpm + unit | same | ✅ |
| T16 | benchmark/xtask | none | none | ✅ |

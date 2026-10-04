# Publish the CTAP 2.1 Core — Tasks

**Spec:** `.specs/features/ctap-crates/spec.md`
**Design:** `.specs/features/ctap-crates/design.md`
**Testing:** `.specs/codebase/TESTING.md`
**Status:** Draft — blocked on Discuss (C-G1..C-G5) and on security-hardening P1 (C-G5)

## Execution Plan

### Phase 0: Decide

```
A0 (Discuss C-G1..C-G5) → A1 (vstd spike)
```

### Phase 1: Mechanical split (no behaviour change)

```
A1 → A2 → A3 → A4
```

### Phase 2: Public API (parallel after A4)

```
      ┌→ A5 [P] ─┐
A4 ───┼→ A6 [P] ─┼→ A8 → A9
      └→ A7 [P] ─┘
```

### Phase 3: Publish

```
A9 → A10 → A11 → A12
              └→ A13 [P]
```

---

## Task Breakdown

### A0: Resolve gray areas

**What**: Decide C-G1..C-G5 with the user; write `context.md`; add AD-0xx to STATE.md.
**Where**: `.specs/features/ctap-crates/context.md`, `.specs/project/STATE.md`
**Depends on**: None
**Requirement**: CRATE-01, CRATE-05 (decisions feeding them)
**Done when**:
- [ ] Names reserved decision; vstd strategy; MSRV; CTAPHID placement; timing recorded
**Tests**: none

### A1: Spike — build core without vstd

**What**: Prototype the `verus` feature + erase shim on one module (`token.rs`); measure whether `cargo xtask verus` still proves it and plain `cargo build` has no `vstd` in `cargo tree`.
**Where**: `crates/core/Cargo.toml`, `crates/core/src/token.rs`, scratch branch
**Depends on**: A0
**Requirement**: CRATE-01 (and B-003)
**Done when**:
- [ ] Go/no-go recorded in design.md §vstd with evidence (proof count, `cargo tree -e normal` output)
**Tests**: proof (existing)
**Gate**: quick + proof

### A2: Rename/move crates with no logic change

**What**: `crates/core` → `crates/ctap-authenticator`, generic parts of `crates/wire` → `crates/ctap-wire`; `credid`/`gatestore` stay in `passkey-tpm-wire`; CTAPHID framing moves to `ctap-wire::ctaphid`. Update fuzz targets, Kani harness paths, xtask crate lists, `deny.toml`, portability gate (AD-015).
**Where**: `crates/*`, `fuzz/`, `xtask/src/tasks/{verus,kani,portability,fuzz}.rs`
**Depends on**: A1
**Requirement**: CRATE-05, CRATE-06
**Done when**:
- [ ] `cargo xtask ci` green, Verus obligation count unchanged, test count unchanged
- [ ] `cargo xtask kani` (slow tier) and `cargo xtask fuzz --time 60` green
**Tests**: unit + proof + bounded proof + fuzz (moved, unchanged)
**Gate**: fast + proof

### A3: Introduce `CredentialBackend` and `BackendError`

**What**: Replace `tpm_iface::{TpmOps, TpmError, Uid}` with the backend trait from design.md; engine generic over it.
**Where**: `crates/ctap-authenticator/src/backend.rs`, `src/ctap2/*`
**Depends on**: A2
**Requirement**: CRATE-02, CRATE-03
**Done when**:
- [ ] No `Tpm*`/`Uid` names in the engine's public API (`cargo public-api` or rustdoc JSON diff)
- [ ] Scenario tests use a `MockBackend`; Verus green
**Tests**: unit + proof
**Gate**: quick + proof

### A4: passkey-tpm implements the backend

**What**: `passkey-tpm-tpm::TpmBackend: CredentialBackend` (unix uid as `Principal`); uvd wired to it; TPM gate selection moved from `core::gates`.
**Where**: `crates/tpm/src/adapter.rs`, `crates/tpm/src/gates.rs`, `crates/uvd/src/lib.rs`
**Depends on**: A3
**Requirement**: CRATE-07, CRATE-08
**Done when**:
- [ ] `cargo xtask ci` green; VM test bed green (same 38+ scenarios)
**Tests**: integration-tpm + integration-dbus + vm-e2e
**Gate**: fast + `cargo xtask vm`

### A5: `#[non_exhaustive]` and visibility pass [P]

**What**: Mark extensible public enums/structs `#[non_exhaustive]`; make internals `pub(crate)`; add `missing_docs = "deny"` for both crates.
**Where**: `crates/ctap-authenticator/src/**`, `crates/ctap-wire/src/**`
**Depends on**: A4
**Requirement**: CRATE-04
**Done when**:
- [ ] clippy + rustdoc green with `missing_docs` denied
**Tests**: unit (existing)
**Gate**: quick

### A6: Software-backend example [P]

**What**: `examples/soft-authenticator.rs`: in-memory P-256 backend + a minimal transport (uhid via the agent code path or a loopback socket used by python-fido2).
**Where**: `crates/ctap-authenticator/examples/`, `scripts/e2e_ctap21.py` (target selection)
**Depends on**: A4
**Requirement**: CRATE-02
**Done when**:
- [ ] python-fido2 CTAP 2.1 suite (28 checks) passes against the example
**Tests**: e2e script (local), added to the VM test bed if uhid-based
**Gate**: quick + script run

### A7: Crate metadata and docs [P]

**What**: `readme`, `keywords`, `categories`, `documentation`, `rust-version` per C-G3, `publish = true` on the two crates; README with CTAP 2.1 coverage matrix and a "What is proven" section (Verus obligations, Kani harnesses, fuzz targets, and what is NOT covered — e.g. CBOR `build` loop, see STATE todo).
**Where**: `crates/ctap-*/Cargo.toml`, `crates/ctap-*/README.md`, `src/lib.rs` crate docs
**Depends on**: A4
**Requirement**: CRATE-11
**Done when**:
- [ ] `cargo doc --no-deps` clean; README renders on a `cargo package --list` check
**Tests**: none (docs) — doctests compile
**Gate**: build

### A8: `cargo xtask publish-check` in CI

**What**: New xtask step running `cargo publish --dry-run` for both crates in order; added to `ci.yml` matrix.
**Where**: `xtask/src/tasks/publish_check.rs`, `xtask/src/tasks/mod.rs`, `.github/workflows/ci.yml`
**Depends on**: A5, A6, A7
**Requirement**: CRATE-10
**Done when**:
- [ ] Step green locally and in PR CI
**Tests**: none (gate = running the task)
**Gate**: build

### A9: Publish workflow with Trusted Publishing

**What**: `.github/workflows/publish-crates.yml` triggered by `ctap-wire-v*` / `ctap-authenticator-v*` tags; fast gate, then `cargo publish` with crates.io OIDC Trusted Publishing; actions pinned by SHA (verify the current official action at task time).
**Where**: `.github/workflows/publish-crates.yml`
**Depends on**: A8
**Requirement**: CRATE-09
**Done when**:
- [ ] Workflow lints (actionlint) and dry-runs on a fork
**Tests**: none
**Gate**: build

### A10: Configure crates.io (manual, user)

**What**: Reserve names by first publish; enable Trusted Publishing for this repo/workflow on both crates. Irreversible — needs explicit user go-ahead.
**Depends on**: A9
**Requirement**: CRATE-09
**Done when**:
- [ ] Both crates show the GitHub trusted publisher

### A11: Publish 0.1.0-alpha.1

**What**: Tag `ctap-wire-v0.1.0-alpha.1`, then `ctap-authenticator-v0.1.0-alpha.1`; switch passkey-tpm deps to `path` + `version`.
**Depends on**: A10
**Requirement**: CRATE-07, CRATE-09
**Done when**:
- [ ] docs.rs builds green; passkey-tpm main builds against the published versions
**Gate**: fast

### A12: Update research and roadmap

**What**: Mark ROADMAP "Future: upstream the verified crates" done; record versions in STATE.
**Depends on**: A11
**Tests**: none

### A13: Outreach [P]

**What**: Announce to linux-credentials (Matrix, credentialsd #8/#26); open a passkey-types discussion for clientPin/credMgmt types.
**Depends on**: A11
**Requirement**: CRATE-12
**Tests**: none

---

## Validation

**Diagram ↔ definitions**

| Task | Depends on (definition) | Diagram | OK |
|---|---|---|---|
| A0 | None | start | ✅ |
| A1 | A0 | A0 → A1 | ✅ |
| A2 | A1 | A1 → A2 | ✅ |
| A3 | A2 | A2 → A3 | ✅ |
| A4 | A3 | A3 → A4 | ✅ |
| A5, A6, A7 | A4 | A4 → [P] | ✅ |
| A8 | A5, A6, A7 | join → A8 | ✅ |
| A9 | A8 | A8 → A9 | ✅ |
| A10 | A9 | A9 → A10 | ✅ |
| A11 | A10 | A10 → A11 | ✅ |
| A12, A13 | A11 | A11 → A12, A13 [P] | ✅ |

**Test co-location**

| Task | Layer | Required | In task | OK |
|---|---|---|---|---|
| A1, A3 | core state machines | unit + proof | yes | ✅ |
| A2 | core + codecs (moved) | unit + proof + bounded proof + fuzz | yes | ✅ |
| A4 | TPM shell + D-Bus services | integration-tpm + integration-dbus | yes (+ vm-e2e) | ✅ |
| A5 | core + codecs | unit (existing) | yes | ✅ |
| A6 | example / e2e | e2e script | yes | ✅ |
| A0, A7–A13 | docs / config / CI | none | none | ✅ |

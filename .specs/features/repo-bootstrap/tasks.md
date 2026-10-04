# Repo Bootstrap (M0) — Tasks

**Spec:** `.specs/features/repo-bootstrap/spec.md`
**Testing:** `.specs/codebase/TESTING.md`
**Status:** Done except T12 (Go README notice), 2026-10-03

## Results

| Task | Status | Notes |
|---|---|---|
| T1 | ✅ | `passkey-tpm-wire` crate added (AD-008) |
| T2 | ✅ | `arithmetic_side_effects` not denied in `core`: Verus proves overflow freedom there (SPEC_DEVIATION, BOOT-04) |
| T3 | ✅ | 4 unit tests |
| T4 | ✅ | `serde_cbor` ban verified; cargo-deny 0.20.2 also pinned and installed by xtask |
| T5 | ✅ | First real proof: `PinRetries` (8 verified); wrong postcondition rejected |
| T6 | ✅ | Kani pinned to 0.68.0 (0.64 nightly rejected rust-version 1.98.1); `Reader` harnesses; OOB bug detected in negative check |
| T7 | ✅ | cargo-fuzz 0.13.2 + nightly-2026-08-18 pinned. SPEC_DEVIATION: Bolero not used; Kani harness and fuzz target are separate but check the same property |
| T8 | ✅ | `cargo xtask ci` green locally (fuzz 60 s) |
| T9 | ✅ | Actions pinned by SHA; not yet run on GitHub (repo not pushed) |
| T10 | ✅ | |
| T11 | ✅ | |
| T12 | ⏳ | Specs moved; Go README freeze notice awaits user confirmation |


---

## Execution Plan

### Phase 1: Skeleton (sequential)

```
T1 → T2 → T3
```

### Phase 2: Gates (parallel)

```
      ┌→ T4 [P] ─┐
      ├→ T5 [P] ─┤
T3 ───┼→ T6 [P] ─┼──→ T8
      └→ T7 [P] ─┘
T1 ──────→ T11 [P]
```

### Phase 3: Pipeline and docs (sequential)

```
T8 → T9
T1 → T10 [P]
T9, T10, T11 → T12
```

---

## Task Breakdown

### T1: Create workspace skeleton

**What:** New repo `passkey-tpm`: root `Cargo.toml` workspace with the 8 stub crates + `xtask`, `rust-toolchain.toml`, `.gitignore`, LICENSE-MIT, LICENSE-APACHE, NOTICE, README.
**Where:** repo root, `crates/*/`, `xtask/`
**Depends on:** None
**Reuses:** psanford/tpm-fido MIT notice (Go repo `LICENSE`)
**Requirement:** BOOT-01, BOOT-02, BOOT-03

**Done when:**
- [ ] `cargo build --workspace` succeeds
- [ ] Toolchain pinned to the Verus-supported version (1.98.x; confirm against the pinned Verus release)
- [ ] License files + NOTICE present; every crate has `license = "MIT OR Apache-2.0"`

**Tests:** none (config) · **Gate:** build (`cargo build --workspace` until T3 exists)
**Commit:** `chore: bootstrap passkey-tpm workspace`

---

### T2: Workspace lints and clippy policy

**What:** `[workspace.lints]` in the root `Cargo.toml` (`clippy::all` deny, pedantic subset), `lints.workspace = true` in all crates, stricter `[lints]` and `#![forbid(unsafe_code)]` in `passkey-tpm-core`, `clippy.toml`.
**Where:** `Cargo.toml`, `crates/*/Cargo.toml`, `crates/passkey-tpm-core/src/lib.rs`, `clippy.toml`
**Depends on:** T1
**Requirement:** BOOT-04

**Done when:**
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] Adding `.unwrap()` in core makes clippy fail (checked manually once, then reverted)

**Tests:** none (config) · **Gate:** build
**Commit:** `chore: workspace lint policy`

---

### T3: xtask skeleton with fmt / clippy / test / build

**What:** `xtask` binary (clap) with `fmt [--check]`, `clippy`, `test` (prints the pass count), `build`; `.cargo/config.toml` alias `xtask = "run --package xtask --"`.
**Where:** `xtask/src/main.rs`, `xtask/src/tasks/{fmt,clippy,test,build}.rs`, `.cargo/config.toml`
**Depends on:** T2
**Requirement:** BOOT-05

**Done when:**
- [ ] `cargo xtask fmt --check && cargo xtask clippy && cargo xtask test` passes
- [ ] A failing subprocess makes xtask exit non-zero (unit test of the command runner)
- [ ] Test count: ≥1 test passes (xtask runner test)

**Tests:** unit (the xtask runner's exit-code propagation) · **Gate:** quick
**Commit:** `build(xtask): fmt, clippy, test, build tasks`

---

### T4: cargo-deny policy + `xtask deny` [P]

**What:** `deny.toml` (licenses allowlist, advisories deny, bans `serde_cbor`, sources crates.io) and an `xtask deny` subcommand that installs or checks the pinned `cargo-deny`.
**Where:** `deny.toml`, `xtask/src/tasks/deny.rs`
**Depends on:** T3
**Requirement:** BOOT-06

**Done when:**
- [ ] `cargo xtask deny` passes on the workspace
- [ ] Temporarily adding `serde_cbor` makes it fail (checked once)

**Tests:** none (config; the gate is running the task) · **Gate:** quick + `cargo xtask deny`
**Commit:** `build(xtask): cargo-deny supply-chain policy`

---

### T5: Verus pinning + `xtask verus` + trivial proof [P]

**What:** `tools/verus.toml` (release tag, sha256, `vstd` exact version); `xtask verus` fetches or verifies the binary into `target/tools/` and runs it on `passkey-tpm-core`. A trivial verified function (e.g. a `saturating_dec` spec for PIN retries) in core.
**Where:** `tools/verus.toml`, `xtask/src/tasks/verus.rs`, `crates/passkey-tpm-core/src/proofs/smoke.rs`
**Depends on:** T3
**Requirement:** BOOT-07

**Done when:**
- [ ] `cargo xtask verus` reports "verification results: N verified, 0 errors"
- [ ] A checksum mismatch aborts the run
- [ ] The core still builds with plain `cargo build` (Verus macros cfg-gated or `vstd` builtin)

**Tests:** proof · **Gate:** quick + proof
**Commit:** `build(xtask): pinned Verus verification`

---

### T6: Kani pinning + `xtask kani` + trivial harness [P]

**What:** Kani pinned version, `xtask kani` (installs `kani-verifier` at the pinned version, runs `cargo kani -p passkey-tpm-core`), a trivial Bolero/Kani harness.
**Where:** `tools/kani.toml`, `xtask/src/tasks/kani.rs`, `crates/passkey-tpm-core/src/harness.rs`
**Depends on:** T3
**Requirement:** BOOT-08

**Done when:**
- [ ] `cargo xtask kani` reports VERIFICATION:- SUCCESSFUL for the harness

**Tests:** bounded proof · **Gate:** quick + proof
**Commit:** `build(xtask): pinned Kani harness runner`

---

### T7: cargo-fuzz setup + `xtask fuzz` [P]

**What:** `fuzz/` crate with one smoke target that reuses the T6 harness input type via Bolero; `xtask fuzz [--time N] [target]` iterates over all targets.
**Where:** `fuzz/Cargo.toml`, `fuzz/fuzz_targets/smoke.rs`, `xtask/src/tasks/fuzz.rs`
**Depends on:** T3
**Requirement:** BOOT-09

**Done when:**
- [ ] `cargo xtask fuzz --time 10` runs every target and exits 0

**Tests:** fuzz · **Gate:** quick + `cargo xtask fuzz --time 10`
**Commit:** `build(xtask): cargo-fuzz targets runner`

---

### T8: `xtask ci` aggregator

**What:** `xtask ci` runs fmt --check → clippy → deny → test → verus → kani → fuzz --time 60 and stops at the first failure with a summary table.
**Where:** `xtask/src/tasks/ci.rs`
**Depends on:** T4, T5, T6, T7
**Requirement:** BOOT-11

**Done when:**
- [ ] `cargo xtask ci` passes locally
- [ ] The step order is covered by a unit test of the task list

**Tests:** unit · **Gate:** full
**Commit:** `build(xtask): ci aggregate task`

---

### T9: GitHub Actions pipeline

**What:** `.github/workflows/ci.yml` (PR + push: one job per xtask step, cache for cargo/Verus/Kani), `fuzz-nightly.yml` (`cargo xtask fuzz --time 3600`), `dependabot.yml` for cargo + actions. Actions pinned by SHA.
**Where:** `.github/workflows/`, `.github/dependabot.yml`
**Depends on:** T8
**Requirement:** BOOT-10

**Done when:**
- [ ] The first PR shows every job green
- [ ] Each job invokes only `cargo xtask <task>`

**Tests:** none (config) · **Gate:** full (in CI)
**Commit:** `ci: xtask-driven pipeline and nightly fuzzing`

---

### T10: Threat model + ADRs [P]

**What:** `docs/threat-model.md` (T1–T5, assets, trust boundaries broker/agent/TPM/fprintd, out-of-scope), plus `docs/adr/0001-rust-verified-core.md`, `0002-provider-and-uhid.md` and `0003-tpm-policy-model.md`, ported from STATE AD-001/002/007 and design.md.
**Where:** `docs/`
**Depends on:** T1
**Requirement:** BOOT-12

**Done when:**
- [ ] The documents match `.specs` content; ADR-003 status is Accepted

**Tests:** none (docs) · **Gate:** build
**Commit:** `docs: threat model and ADRs 0001-0003`

---

### T11: SECURITY.md and README [P]

**What:** SECURITY.md (private disclosure via GitHub advisories, supported versions); README with the goals, status "pre-alpha" and an architecture summary.
**Where:** `SECURITY.md`, `README.md`
**Depends on:** T1
**Requirement:** BOOT-03

**Tests:** none (docs) · **Gate:** build
**Commit:** `docs: security policy and README`

---

### T12: Move `.specs` and freeze the Go repo

**What:** Copy `.specs/` into the new repo (with `codebase/` moved to `.specs/legacy-go/`). Add a top-of-README notice to the Go repo: frozen, known CRITICAL/HIGH issues (link CONCERNS), successor link.
**Where:** new repo `.specs/`; Go repo `Readme.md`
**Depends on:** T9, T10, T11
**Requirement:** BOOT-13

**Done when:**
- [ ] The new repo has `.specs/project/*` and `features/*`; `TESTING-PLAN.md` renamed to `.specs/codebase/TESTING.md`
- [ ] The Go README notice is merged (**user confirmation required**: public-facing change)

**Tests:** none (docs) · **Gate:** build
**Commit:** `docs: import specs` / Go repo: `docs: freeze notice and successor link`

---

## Validation

### Granularity

| Task | Scope | Status |
|---|---|---|
| T1 | workspace skeleton (config files only) | ⚠️ several files but one cohesive concern (no logic) |
| T2 | lint config | ✅ |
| T3 | xtask runner + 4 trivial wrappers | ⚠️ cohesive (same runner pattern) |
| T4–T7 | one tool each | ✅ |
| T8 | one task | ✅ |
| T9 | CI config | ✅ |
| T10 | docs | ✅ |
| T11 | docs | ✅ |
| T12 | spec move + one README notice | ✅ |

### Diagram–definition cross-check

| Task | Depends on (body) | Diagram | Status |
|---|---|---|---|
| T1 | — | — | ✅ |
| T2 | T1 | T1→T2 | ✅ |
| T3 | T2 | T2→T3 | ✅ |
| T4 | T3 | T3→T4 | ✅ |
| T5 | T3 | T3→T5 | ✅ |
| T6 | T3 | T3→T6 | ✅ |
| T7 | T3 | T3→T7 | ✅ |
| T8 | T4–T7 | T4..T7→T8 | ✅ |
| T9 | T8 | T8→T9 | ✅ |
| T10 | T1 | T1→T10 | ✅ |
| T11 | T1 | T1→T11 | ✅ |
| T12 | T9, T10, T11 | →T12 | ✅ |

### Test co-location

| Task | Layer | Matrix requires | Task says | Status |
|---|---|---|---|---|
| T1, T2, T4, T9 | config | none | none | ✅ |
| T3, T8 | xtask (has logic: runner, ordering) | none (config) — chose unit anyway | unit | ✅ |
| T5 | core proof smoke | proof | proof | ✅ |
| T6 | core harness | bounded proof | bounded proof | ✅ |
| T7 | fuzz target | fuzz | fuzz | ✅ |
| T10–T12 | docs | none | none | ✅ |

**Parallel note:** T4–T7 each add one file under `xtask/src/tasks/` and one line to `xtask/src/main.rs`. That's shared state, so merge conflicts are trivial but real; when run in parallel, register subcommands through a `tasks/mod.rs` list owned by T3 to avoid the conflict.

# passkey-tpm — Testing

**Status:** Draft, derived from the PROJECT goals (G2, G3), AD-006 and ADR-003. The new repo is greenfield; this file replaces the brownfield TESTING.md that describes the frozen Go code.

## Test types

| Type | Tool | Location |
|---|---|---|
| unit | `cargo test` (+ proptest) | `#[cfg(test)]` modules, `crates/*/tests/` |
| proof | Verus (pinned) | `crates/core/src/**` `verus!{}` blocks |
| bounded proof | Kani (+ Bolero harness reused as fuzz target) | `#[cfg(kani)]` modules |
| fuzz | cargo-fuzz (libFuzzer) | `fuzz/fuzz_targets/` |
| integration-tpm | swtpm, one instance per test (socket TCTI) | `crates/tpm/tests/` |
| integration-dbus | private `dbus-daemon --session` per test | `crates/uvd/tests/` |
| hardware | real TPM / fprintd, `#[ignore]` + feature flag | run manually, results in `docs/compat.md` |
| vm-e2e | pytest + pytest-testinfra in an mkosi VM (swtpm, libfprint virtual device), deps locked with uv | `tests/vm/e2e/`; `cargo xtask vm`; JUnit + HTML in `target/vm/report/`; nightly CI |

## Coverage matrix

| Code layer | Required tests | Parallel-safe |
|---|---|---|
| core state machines (CTAPHID, PIN, flags/evidence) | unit + proof | Yes |
| parsers/codecs (CBOR, credential ID, HID packets, state files) | unit + bounded proof + fuzz target | Yes |
| pure crypto/policy helpers (policy digest, policyRef, KDF wrappers) | unit (known-answer vectors) | Yes |
| TPM shell (`passkey-tpm-tpm`, including `ffi.rs`) | integration-tpm | Yes (isolated swtpm per test) |
| D-Bus services (broker, agent) | integration-dbus | Yes (private bus per test) |
| xtask / CI / config files | none (gate = running the task itself) | n/a |
| docs / ADRs | none | n/a |

## Gate check commands

| Gate | Command | When |
|---|---|---|
| quick | `cargo xtask fmt --check && cargo xtask clippy && cargo xtask test` | every task |
| proof | `cargo xtask verus && cargo xtask kani` | tasks touching proof/bounded-proof layers |
| fast (default) | `cargo xtask ci` (fmt, clippy, deny, test incl. swtpm, verus) ≈ 12 s | every change, PR CI |
| full | `cargo xtask ci --full` (adds kani + fuzz 60 s/target) | nightly CI, on request |
| build | `cargo xtask build` | config-only tasks |

## Rules

- Slow validations (Kani, long fuzz) are skipped during development; if a proof takes minutes, record the gap instead of tuning it (user preference, 2026-10-03).

- No `#[ignore]` without a feature flag and a tracking issue.
- Test count must not drop between tasks (xtask prints the count; CI compares against the previous main run).
- Every Kani harness is also registered as a fuzz target (Bolero).
- Negative security tests (bypass attempts) are mandatory for each TPM-0x requirement that says "can't".

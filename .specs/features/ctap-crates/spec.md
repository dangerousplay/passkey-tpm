# Publish the CTAP 2.1 Core as Standalone Crates — Specification

**Size:** Complex (new public API, crates.io publishing, verification toolchain constraints)
**Status:** Specified. Gray areas C-G1..C-G5 need decisions (Discuss) before Design is approved.
**Research:** `.specs/features/rust-core-rewrite/research-rust-ecosystem.md` (2026-10-04 addendum)

## Problem Statement

No published Rust crate provides a permissively licensed, std-host, authenticator-side CTAP 2.1 engine with clientPIN v2, credentialManagement and hmac-secret (survey 2026-10-04: passkey-authenticator lacks clientPin/credMgmt; Trussed crates are firmware-bound; soft-fido2 is AGPL/GPL; fidorium has no PIN/UV). passkey-tpm already has one, verified with Verus (core) and Kani + fuzzing (wire). Publishing it lets other Linux authenticators (software, TPM, secure-element backends) and credentialsd/libwebauthn reuse it (ROADMAP "Future": upstream the verified crates).

## Goals

- [ ] `ctap-wire` (codecs) and `ctap-authenticator` (engine) on crates.io, MIT OR Apache-2.0
- [ ] passkey-tpm consumes the published crates with no behaviour change (all gates + VM test bed green)
- [ ] Engine is backend-agnostic: an in-memory software backend example passes the python-fido2 CTAP 2.1 suite
- [ ] Releases are published from CI with crates.io Trusted Publishing (no long-lived token), matching the Sigstore-signed package flow

## Out of Scope

| Feature | Reason |
|---|---|
| `no_std` support | Only matters to compete with ctap-types; revisit on demand |
| CTAP 2.2 features (largeBlob, minPinLength, enterprise attestation) | ROADMAP "Future" |
| Publishing the TPM, uvd, agent, uv crates | Project-specific; stay `publish = false` |
| Contributing clientPin/credMgmt types to passkey-types | Optional follow-up, tracked as a deferred idea |

## Gray Areas (Discuss)

| ID | Question | Options | Recommendation |
|---|---|---|---|
| C-G1 | Crate names | `ctap-authenticator` + `ctap-wire` (free 2026-10-04); `verified-ctap`/`vctap`; keep `passkey-tpm-core`/`-wire` | `ctap-authenticator` + `ctap-wire`: describes the role; verification is a property, not a name |
| C-G2 | `vstd` exact pin in a public crate | (a) keep exact pin, document as toolchain contract; (b) make `vstd` optional: ghost code erased under `cfg(not(verus_only))`, exec code compiled plain (B-003) | (b): also unblocks distro packaging (B-003); (a) as fallback |
| C-G3 | MSRV | keep 1.98.1 (Verus pin); lower for plain builds if C-G2(b) works | follow C-G2: lower to the oldest toolchain CI can test for plain builds |
| C-G4 | Where CTAPHID lives | in the engine; in wire; own crate `ctaphid-device` | in `ctap-wire` (framing/assembler are codecs); channel state machine stays in the engine |
| C-G5 | Timing | before or after the beta | after beta P1 hardening; before 0.1.0 is fine — the API is pre-1.0 (`0.1.0-alpha.N`) |

---

## User Stories

### P1: Reusable verified engine ⭐ MVP

**User Story**: As an authenticator developer, I want to add `ctap-authenticator` to my project and implement a credential backend trait, so that I get a CTAP 2.1 authenticator without writing the protocol.

**Acceptance Criteria**:

1. WHEN a crate depends on `ctap-authenticator` THEN it SHALL build with stable cargo without the Verus toolchain (CRATE-01)
2. WHEN the backend trait is implemented by an in-memory software store THEN the example SHALL answer makeCredential, getAssertion, getInfo, clientPIN (protocols 1 and 2), credentialManagement and hmac-secret (CRATE-02)
3. WHEN the engine's public types are used THEN no passkey-tpm-specific names (`TpmOps`, `TpmError`, `Uid`-as-unix-uid, gates) SHALL appear (CRATE-03)
4. WHEN a public enum is matched downstream THEN it SHALL be `#[non_exhaustive]` where future CTAP versions can add variants (CRATE-04)

**Independent Test**: `cargo run --example soft-authenticator` + python-fido2 CTAP 2.1 suite over a socket/uhid shim.

### P1: Hostile-input-safe codecs ⭐ MVP

**User Story**: As a FIDO client or authenticator developer, I want a CTAP CBOR + CTAPHID codec crate that never panics on untrusted bytes.

**Acceptance Criteria**:

1. WHEN `ctap-wire` is published THEN it SHALL contain only CTAP-generic codecs (CBOR, CTAPHID framing, resident-credential metadata); `credid` and `gatestore` SHALL stay in passkey-tpm (CRATE-05)
2. WHEN fuzz targets and Kani harnesses run THEN they SHALL target the published crate's API unchanged (CRATE-06)

### P1: passkey-tpm on the published crates ⭐ MVP

1. WHEN the workspace builds THEN passkey-tpm crates SHALL depend on `ctap-*` by `path` + `version` (CRATE-07)
2. WHEN `cargo xtask ci` and the VM test bed run THEN results SHALL match the pre-extraction baseline (test count must not drop) (CRATE-08)

### P2: Trusted, reproducible publishing

1. WHEN a `ctap-wire-v*` / `ctap-authenticator-v*` tag is pushed THEN CI SHALL publish with crates.io Trusted Publishing (OIDC) after the fast gate (CRATE-09)
2. WHEN `cargo publish --dry-run` runs in PR CI THEN packaging errors SHALL fail the PR (CRATE-10)

### P2: Documentation of guarantees

1. WHEN a user reads the crate docs THEN they SHALL find a CTAP 2.1 coverage matrix and exactly what Verus/Kani/fuzzing prove and don't (CRATE-11)

### P3: Upstream outreach

1. WHEN the crates are published THEN linux-credentials (credentialsd/libwebauthn) SHALL be told, and a passkey-types proposal for clientPin/credMgmt types considered (CRATE-12)

---

## Edge Cases

- WHEN a downstream crate also depends on a different `vstd` THEN, with C-G2(b), no `vstd` SHALL be pulled in a plain build
- WHEN the backend returns an error mid-operation THEN the engine SHALL map it to a CTAP status without panicking (existing never-panic proptests extended to the trait boundary)
- WHEN a release of `ctap-authenticator` needs a newer `ctap-wire` THEN wire SHALL be published first (publish order enforced in the workflow)

---

## Requirement Traceability

| ID | Story | Prio | Phase | Status |
|---|---|---|---|---|
| CRATE-01 | Reusable engine | P1 | Design (C-G2) | Pending |
| CRATE-02 | Reusable engine | P1 | Design | Pending |
| CRATE-03 | Reusable engine | P1 | Design | Pending |
| CRATE-04 | Reusable engine | P1 | Tasks | Pending |
| CRATE-05 | Codecs | P1 | Design (C-G4) | Pending |
| CRATE-06 | Codecs | P1 | Tasks | Pending |
| CRATE-07 | passkey-tpm migration | P1 | Tasks | Pending |
| CRATE-08 | passkey-tpm migration | P1 | Tasks | Pending |
| CRATE-09 | Publishing | P2 | Tasks | Pending |
| CRATE-10 | Publishing | P2 | Tasks | Pending |
| CRATE-11 | Docs | P2 | Tasks | Pending |
| CRATE-12 | Outreach | P3 | Tasks | Pending |

**Coverage:** 12 total, 12 mapped to tasks, 0 unmapped

## Success Criteria

- [ ] `ctap-authenticator` and `ctap-wire` 0.1.0-alpha.1 on crates.io, docs.rs builds green
- [ ] Software-backend example passes the same python-fido2 CTAP 2.1 checks as passkey-tpm
- [ ] passkey-tpm main builds against the published versions

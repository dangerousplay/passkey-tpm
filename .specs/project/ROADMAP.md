# Roadmap

**Current Milestone:** M1 — Verified Core + TPM (MVP-1)
**Status:** In Progress (M0 complete 2026-10-03, except the Go-repo freeze notice)

## MVP slices

Each MVP is a usable, demoable cut of a milestone. Later milestones harden and widen it.

| MVP | Milestone | User-visible outcome | Cut line |
|---|---|---|---|
| MVP-0 | M0 | Green `cargo xtask ci` with real proofs (Verus, Kani) and fuzzing | done |
| MVP-1 (code complete, hardware E2E pending) | M1 | Register and sign in on webauthn.io with fingerprint, keys enforced by TPM policy, on any TPM 2.0 + fprintd laptop | makeCredential/getAssertion over uhid; broker + agent; fprintd UV + presence; non-discoverable credentials; no PIN, no hmac-secret in the protocol (the TPM side lands in M1 but is wired in MVP-2) |
| MVP-2 (done; real-fprintd E2E pending) | M1 + M2 | Discoverable passkeys, PIN, hmac-secret/PRF, and `systemd-cryptenroll`/`pam_u2f` working | clientPIN v2, credMgmt, hmac-secret, credProtect; compat matrix |
| MVP-3 (in progress) | M3 | Installable from COPR/AUR/PPA with distro-neutral units and polkit | packaging + security review |
| MVP-4 | M4 | Works through credentialsd/portal and has a management UI | provider API + UI |


---

## M0 — Foundation — COMPLETE (MVP-0)

**Goal:** New repo bootstrapped with verification CI and decisions recorded, so feature work can start.
**Target:** Repo public; CI green with a trivial Verus proof, a Kani harness and a fuzz target.

### Features

**Repo bootstrap** - COMPLETE

- Repo `passkey-tpm`; Cargo workspace: `core` (verified, sync, `#![forbid(unsafe_code)]`), `tpm`, `uv`, `transport-uhid`, `provider-dbus`, `daemon`, `cli`, `xtask`
- `cargo xtask` (alias in `.cargo/config.toml`): `fmt`, `clippy`, `test`, `deny`, `verus`, `kani`, `fuzz [--time]`, `ci` (runs all gates in CI order), `dist` (release tarball, man pages, completions, unit files)
- Clippy policy: `[workspace.lints]` in root `Cargo.toml`; `-D warnings`; `core` also denies `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`
- `deny.toml`: license allowlist (MIT, Apache-2.0, BSD-*, ISC, Unicode-3.0, Zlib; LGPL only across process boundaries), RustSec advisories = deny, bans (`serde_cbor`, multiple versions = warn), sources = crates.io only
- Pin rust-toolchain + Verus release + exact `vstd`; CI pipeline (GitHub Actions, each job = `cargo xtask <task>`): fmt → clippy → deny → test → verus → kani → fuzz smoke test (PR) / long fuzz run (nightly); `cargo xtask ci` reproduces the pipeline locally
- MIT OR Apache-2.0, NOTICE crediting psanford/tpm-fido, SECURITY.md, threat model doc

**Upstream engagement** - PLANNED

- Contact linux-credentials (Matrix, credentialsd #8/#26): propose the provider D-Bus interface
- Comment on authd #709/#1610 with the broker-gated biometrics proposal (see M4)

**ADRs** - PLANNED

- ADR-001 Rust + verified core, ADR-002 Provider + uhid, ADR-003 TPM key policy model, ADR-004 types crate (ctap-types vs passkey-types)

---

## M1 — Verified Core + TPM (MVP over uhid)

**Goal:** Feature parity with the Go daemon over uhid, with every Go CRITICAL/HIGH concern fixed by design. Daily-driveable on any TPM 2.0 + fprintd laptop.

### Features

**Verified CTAP core** - COMPLETE (MVP-1 scope)

- CTAPHID state machine (CID allocation, SEQ order, max length, busy/cancel/keepalive, per-channel lock): Verus
- CBOR decode with depth/length limits: Kani panic-freedom plus fuzzing
- Auth data builder that requires a UP/UV evidence token (ghost/linear): Verus
- getNextAssertion bound to channel and request, with a 30 s expiry
- allowList/excludeList bounds enforced (`maxCredentialCountInList`)

**TPM backend** - COMPLETE (library; hardware benchmark pending) (spec: `.specs/features/tpm-policy-model/`)

- ADR-003: privileged broker + per-user `PolicyOR(PolicySecret PIN/UV/UP gates)`, with policyRef bound to rpIdHash
- Persistent TCG SRK 0x81000001 with its Name pinned; salted, parameter-encrypted sessions
- hmac-secret: two TPM keyedHash HMAC keys per credential (WithUV / WithoutUV)
- PIN gate on an NV index (`NV_ChangeAuth`, Argon2id); counter always 0
- Benchmark on AMD fTPM, Intel PTT and a dTPM (≤ 500 ms p95)

**Broker/agent split** - COMPLETE (MVP-1 scope)

- `passkey-tpm-uvd` system service (dedicated user, systemd hardening, D-Bus system API, caller uid from bus credentials, polkit grant for fprintd)
- `passkey-tpm-agent` user service (uhid + UI only; untrusted)

**User verification providers** - COMPLETE (MVP-1 scope)

- `UvProvider` trait; fprintd provider (zbus proxy generated from introspection XML), honouring polkit/active session
- Prompt names the RP ID; cancel works

**uhid transport + daemon** - COMPLETE (MVP-1 scope)

- Port of the scoped uhid code; udev `uaccess` tag (no plugdev); systemd user unit with sd-notify
- Physical-key auto-switch generalised (any FIDO HID usage page, not only Yubico VID)

**Resident credential store** - PLANNED

- Atomic writes (temp + fsync + rename), mode 0600, schema version, refuses to overwrite a corrupt file

---

## M2 — CTAP 2.1 Completeness & Compatibility

**Goal:** Passes conformance tooling; works as a LUKS/homed token and with pam_u2f.

### Features

**CTAP 2.1 commands** - COMPLETE

- clientPIN protocol 2 (retries proven in Verus), PIN as a UV provider, reset, selection, credentialManagement, credProtect, credProps, hmac-secret/PRF
- Attestation: `none` by default; optional TPM-backed `packed` attestation with a per-install certificate (decided in an ADR)

**Compatibility matrix** - PLANNED

- FIDO conformance tools, `fido2-token`, Chromium/Chrome/Firefox, `pam_u2f`, `systemd-cryptenroll --fido2-device`
- Snap/Flatpak notes; note the Chromium `plat:true` limitation

**System mode** - PLANNED

- Pre-login use (GDM/LUKS) through the system broker; agent-less transport for early boot

---

## M3 — Distribution

**Goal:** Installable from official or near-official channels.

### Features

**Packaging** - IN PROGRESS (`xtask dist`, PKGBUILD, Fedora spec, debian/ written; not yet built in clean chroots)

- Debian: debcargo-friendly deps; file an ITP; upload missing crates (or avoid them)
- Fedora: spec plus COPR, then a review request; Arch: PKGBUILD/AUR; openSUSE OBS
- Distro-neutral polkit actions (`<id>.credential.create/reset/manage`, auth_self_keep), udev rule, systemd units, man pages

**Security review** - PLANNED

- External review; fuzzing in OSS-Fuzz; reproducible builds

---

## M4 — Desktop & Ecosystem Integration

**Goal:** First-class desktop experience and portal-based access.

### Features

**credentialsd provider** - PLANNED

- Implement the agreed provider D-Bus interface; the UI is delegated to credentialsd-ui; works with sandboxed apps through the Credentials portal

**Management UI** - PLANNED

- A libadwaita app (or GNOME/KDE settings panels): list and delete passkeys, change the PIN, view status
- **authd/Entra use case:** a fingerprint enrollment flow behind an admin opt-in polkit action, for users that GNOME Settings hides it from. Respect the broker-bypass concern: verifying for passkeys is allowed, using fingerprints for login stays an admin policy. Upstream proposal: a broker `allow_local_biometrics` key plus re-validation in the pam_authd account phase

---

## Future Considerations

- More UV providers: face (once a production-grade stack exists), smartcard/PIV, match-on-chip fingerprint
- Native PAM module with broker re-validation (authd/SSSD)
- largeBlob, minPinLength, enterprise attestation
- TPM-less fallback (software keystore + secure enclave alternatives) for machines without a TPM
- Upstream the verified CTAPHID/CBOR crates for reuse by credentialsd/libwebauthn

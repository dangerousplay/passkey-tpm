# Beta Release v0.1.0-beta.1 — Specification

**Size:** Medium (design inline, tasks below)
**Status:** In progress. Release engineering is done on branch `release/v0.1.0-beta.1` (not pushed); the tag is gated on the security-hardening P1 fixes (REL-06).

## Problem Statement

There is no installable build yet. Testers need `.deb`, `.rpm` and Arch packages from GitHub Releases, and they need a way to check that a package was built by this repository's CI from a tagged commit, without the project managing signing keys.

## Goals

- [x] A `v*-beta.N` tag produces `.deb`, `.rpm` and `.pkg.tar.zst` packages, a source tarball and `checksums.txt` as a draft pre-release
- [x] Every package and `checksums.txt` has a keyless Sigstore signature tied to the release workflow identity
- [x] Every checksummed file has SLSA build provenance (GitHub attestation)
- [x] Pre-release versions sort before the final release in dpkg, rpm and pacman
- [x] `v0.1.0-beta.1` published after the P1 security fixes land (2026-10-04)

## Out of Scope

| Feature | Reason |
|---|---|
| GPG-signed repositories (apt/dnf/pacman repo metadata) | Needs a long-lived key and hosting; revisit with COPR/PPA/AUR in M3 |
| Native package signatures (`dpkg-sig`, `rpm --addsign`, pacman `.sig`) | Same key-management cost; Sigstore bundles cover integrity and origin |
| aarch64 packages | GoReleaser builds the CLI for the native target only; add a cross build later |
| crates.io publishing | Separate feature: `.specs/features/ctap-crates/` |

---

## User Stories

### P1: Signed beta packages ⭐ MVP

**User Story**: As a tester, I want to install a beta package and verify it came from this repository's release workflow, so that I can trust a pre-1.0 security tool.

**Acceptance Criteria**:

1. WHEN a `v*` tag is pushed THEN the release workflow SHALL run the fast gate, build `.deb`/`.rpm`/Arch packages and publish a draft GitHub release (REL-01)
2. WHEN GoReleaser publishes THEN each package and `checksums.txt` SHALL have a `<file>.sigstore.json` bundle signed by cosign with the workflow's OIDC identity (REL-02)
3. WHEN the release finishes THEN `gh attestation verify <file> --repo dangerousplay/passkey-tpm` SHALL succeed for every file in `checksums.txt` (REL-03)
4. WHEN the tag has a pre-release suffix THEN the GitHub release SHALL be marked pre-release and package versions SHALL be `0.1.0~beta.1` (dpkg, rpm) and `0.1.0beta.1` (pacman) (REL-04)
5. WHEN `cargo xtask release` runs locally or in PR CI THEN it SHALL build an unsigned snapshot without an OIDC token (REL-05)

**Independent Test**: push the tag to a fork, download the assets, run the `cosign verify-blob` and `gh attestation verify` commands in `packaging/README.md`, install the `.deb` in the Ubuntu 24.04 VM.

### P1: Beta gated on known high-severity findings ⭐ MVP

**User Story**: As a maintainer, I don't want to hand testers a build with known cross-user or broken-UV bugs.

**Acceptance Criteria**:

1. WHEN the beta tag is created THEN security-hardening requirements HARD-01..HARD-04 SHALL be Verified (REL-06)
2. WHEN the release is published THEN its notes SHALL list the remaining known issues (open HARD-* items) (REL-07)

---

## Edge Cases

- WHEN cosign cannot reach Fulcio/Rekor THEN GoReleaser SHALL fail and leave no published release (the release is a draft until a human publishes it)
- WHEN a user upgrades from `0.1.0beta.1` to `0.1.0` with pacman THEN pacman SHALL treat it as an upgrade (`vercmp` = -1, checked)
- WHEN the tag is moved or re-pushed THEN the old signatures SHALL no longer match the new artifacts (verification fails, as intended)

---

## Requirement Traceability

| ID | Story | Phase | Status |
|---|---|---|---|
| REL-01 | Signed beta packages | Execute | Verified (run 37243451613) |
| REL-02 | Signed beta packages | Execute | Verified (cosign verify-blob on v0.1.0-beta.1 assets) |
| REL-03 | Signed beta packages | Execute | Verified (gh attestation verify) |
| REL-04 | Signed beta packages | Execute | Verified (local tag snapshot + `vercmp`) |
| REL-05 | Signed beta packages | Execute | Verified |
| REL-06 | Gated beta | Execute | Verified (HARD-01..04 before tag) |
| REL-07 | Gated beta | Execute | Verified (known issues in the published notes) |

**Coverage:** 7 total, 7 mapped to tasks, 0 unmapped

## Success Criteria

- [ ] Both verification commands succeed on every asset of the published beta
- [ ] The `.deb` installs and passes the VM test bed's package scenarios

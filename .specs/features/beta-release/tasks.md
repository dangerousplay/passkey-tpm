# Beta Release v0.1.0-beta.1 — Tasks

**Spec:** `.specs/features/beta-release/spec.md`
**Testing:** `.specs/codebase/TESTING.md` (xtask/CI/config layer: gate = running the task)
**Status:** In progress

## Execution Plan

```
Done (branch release/v0.1.0-beta.1):  B1 ─ B2 ─ B3 ─ B4 ─ B5

Next:  B6 → B7 ──────────────┐
                             ├→ B9 → B10 → B11 → B12
       security-hardening P1 ┘
       B8 [P] (any time before B11)
```

## Results

| Task | Status | Commit | Notes |
|---|---|---|---|
| B1: Upgrade dependencies to latest stable | ✅ | 6f255a4 | RustCrypto 0.11/0.13 stack, p256 0.14, aes 0.9, cbc 0.2 (`alloc`), getrandom 0.4, zeroize 1.9; `pin_protocol` ported to cipher 0.5 / hybrid-array / `ToSec1Point`. tss-esapi stays 7.7 (8.0 alpha), vstd stays pinned (AD-009). `cargo xtask ci` green |
| B2: Sigstore signing in GoReleaser | ✅ | 803f7a8 | `signs:` entries for `package` and `checksum`, `.sigstore.json` bundles; snapshot uses `--skip=publish,sign` (xtask unit test updated) |
| B3: Release workflow OIDC + provenance | ✅ | 803f7a8 | `id-token: write`, `attestations: write`; cosign-installer v4.1.2 (cosign v3.1.3), attest-build-provenance v4.2.2 over `checksums.txt`; actions pinned by SHA |
| B4: Arch pre-release version | ✅ | 803f7a8 | nfpm drops `Prerelease` for Arch unless an epoch is set → `epoch: "0"` override (L-010) |
| B5: Version bump + recipes | ✅ | dde4fa5 | workspace `0.1.0-beta.1`; Debian `0.1.0~beta.1-1`; Fedora `Version: 0.1.0~beta.1` + `upstream_version`; PKGBUILD `pkgver=0.1.0beta1`, `_tag`. Also untracked `scripts/__pycache__` (1192a89) |

## Task Breakdown (remaining)

### B6: Push branch and open PR

**What**: Push `release/v0.1.0-beta.1`, open a PR to `main`.
**Depends on**: B1–B5
**Requirement**: REL-01, REL-05
**Done when**:
- [ ] PR CI green, including the `release` snapshot step (proves `--skip=publish,sign` and the `signs:` config parse on the runner)
**Tests**: none (CI is the gate)

### B7: Rehearse the signed release on a fork

**What**: Push a throwaway tag (e.g. `v0.0.0-rc.1`) to a fork to exercise cosign + attestation end to end without touching the real release page.
**Depends on**: B6
**Requirement**: REL-02, REL-03
**Done when**:
- [ ] Draft release has `.sigstore.json` for the 3 packages and `checksums.txt`
- [ ] `cosign verify-blob` (identity regexp adjusted to the fork) and `gh attestation verify` pass for every asset
- [ ] Fork tag and draft release deleted
**Tests**: none (manual verification, record output in this file)

### B8: Regenerate CHANGELOG.md [P]

**What**: `cargo xtask changelog` after the hardening fixes merge, so the beta section lists them.
**Where**: `CHANGELOG.md` (generated, never hand-edited — AD-016)
**Depends on**: none (rerun right before B10)
**Requirement**: REL-07
**Done when**:
- [ ] `CHANGELOG.md` regenerated and committed
**Tests**: none

### B9: Merge hardening P1 (gate)

**What**: Confirm HARD-01..HARD-04 are Verified in `.specs/features/security-hardening/spec.md`.
**Depends on**: security-hardening H1–H7
**Requirement**: REL-06
**Done when**:
- [ ] Traceability table shows HARD-01..04 Verified; VM test bed green

### B10: Tag v0.1.0-beta.1

**What**: Merge the PR, tag `v0.1.0-beta.1` on `main` (signed tag; the repo's git config requires a message), push the tag.
**Depends on**: B6, B7, B8, B9
**Requirement**: REL-01..04
**Done when**:
- [ ] Release workflow green; draft pre-release exists with all assets and bundles

### B11: Verify and annotate the draft

**What**: Run the verification commands from `packaging/README.md` on the real assets; add a "Known issues" section listing open HARD-* items.
**Depends on**: B10
**Requirement**: REL-03, REL-07
**Done when**:
- [ ] All assets verify; known issues in the release notes

### B12: Publish and smoke-test

**What**: Publish the draft; install the `.deb` from the release in the Ubuntu 24.04 VM (`cargo xtask vm`).
**Depends on**: B11
**Done when**:
- [ ] Release public, marked pre-release; VM package scenarios pass with the downloaded `.deb`

## Validation

| Task | Depends on (definition) | Diagram | Tests per matrix | OK |
|---|---|---|---|---|
| B6 | B1–B5 | B5 → B6 | none (CI config) | ✅ |
| B7 | B6 | B6 → B7 | none | ✅ |
| B8 | none | [P] | none (docs) | ✅ |
| B9 | hardening H1–H7 | hardening → B9 | n/a (gate) | ✅ |
| B10 | B6, B7, B8, B9 | B7/B9 → B10, B8 before | none | ✅ |
| B11 | B10 | B10 → B11 | none | ✅ |
| B12 | B11 | B11 → B12 | vm-e2e | ✅ |

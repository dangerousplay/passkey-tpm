# passkey-tpm — Linux Passkey Provider

> Successor to `tpm-fido2-thinkpad-linux` (Go, frozen). New repository, Rust.

**Vision:** A production-ready, distro-agnostic passkey (FIDO2/WebAuthn) provider for Linux that binds credentials to the machine's hardware (TPM 2.0) and verifies the user with local secure methods (fingerprint today; PIN, face and others later). The security-critical core is formally verified.
**For:** Linux desktop users and distributions (Debian/Ubuntu, Fedora, Arch, openSUSE), including users managed centrally (authd with Entra ID/Google, SSSD).
**Solves:** Linux has no built-in platform authenticator like Windows Hello or macOS Touch ID. Existing projects are hardware- or distro-specific, are unverified, or give weak security guarantees (software-only user-verification gates, extractable PRF secrets).

## Goals

- **G1 — Security close to hardware keys.** Other users and other processes can't use a credential directly through `/dev/tpmrm0` (keys are policy-bound to a secret held by the daemon or derived from the PIN). Its secrets (private keys, hmac-secret CredRandom) can't be computed off the TPM. The TPM enforces per-user PolicySecret gates held only by the privileged broker `passkey-tpm-uvd` (ADR-003), so malware running as the same user still needs a physical finger or presence gesture, or the PIN. Remaining limit: a spoofed prompt can get a touch approved for a different RP. Metric: zero CRITICAL/HIGH findings in an external review. Every concern in the Go `CONCERNS.md` has a test showing it is fixed.
- **G2 — Verified core.** CTAPHID framing, UP/UV flag evidence, sign counter, PIN retries and credential wrap/unwrap are proven with Verus (`--no-cheating` on the core crate). Kani proves the CBOR/HID parsers panic-free. Metric: proofs run in CI on every PR, and the verified-core TCB file lists every trusted assumption.
- **G3 — Works everywhere it should.** It passes the FIDO conformance tools and libfido2 `fido2-token`. It works with Chromium, Chrome and Firefox over uhid, with `pam_u2f`, and with `systemd-cryptenroll --fido2-device`. Metric: a documented compatibility matrix with CI where automatable.
- **G4 — Distro-includable.** It builds only from crates already packaged in Debian/Fedora where possible. Distro-neutral udev/polkit/systemd units, no group hacks (`uaccess`/logind ACLs). Metric: an ITP filed in Debian, plus a Fedora COPR, then a review request.
- **G5 — Ecosystem alignment.** It provides a credentialsd provider D-Bus interface co-designed with linux-credentials (issues #8 and #26). Metric: an interface proposal accepted or merged upstream.

## Tech Stack

**Core:**

- Language: Rust (stable, pinned to the toolchain Verus supports; 1.98.x as of 2026-10), edition 2021+
- Verification: Verus (pinned release + exact `vstd`), Kani (+ Bolero), cargo-fuzz, proptest
- Runtime: tokio (shell only; the verified core is sync and has no `unsafe`)
- Developer workflow: `cargo xtask` is the single entry point for local work and CI (fmt, clippy, test, deny, verus, kani, fuzz, dist). CI calls only `cargo xtask <task>`, so local and CI behaviour match
- Lint/supply chain: `clippy` (workspace lints in `Cargo.toml`, `-D warnings`, pedantic subset, `unwrap_used`/`panic`/`indexing_slicing` denied in `core`), `cargo-deny` (licenses allowlist, RustSec advisories, bans on duplicate/unmaintained crates such as `serde_cbor`, allowed sources = crates.io only)

**Key dependencies:** `tss-esapi` (tpm2-tss), `zbus` (fprintd, credentialsd, logind, polkit), `ctap-types` or `passkey-types` for message types, `coset` (COSE), `ciborium` (CBOR), RustCrypto `p256`/`ecdsa`, `zeroize`/`secrecy`, `ksni`, `notify-rust`, `sd-notify`.

## Scope

**v1 includes:**

- A verified CTAP 2.1 core: makeCredential, getAssertion, getNextAssertion (channel-bound, expiring), getInfo, reset, selection, clientPIN protocol 2, credential management, hmac-secret, credProtect
- A TPM 2.0 backend: policy-bound keys, a TPM-held hmac-secret CredRandom, and a monotonic counter kept per credential or in TPM NV
- Pluggable user verification (a `UvProvider` trait): fprintd and PIN, with the evidence token consumed by the verified core
- A uhid CTAPHID transport with correct channel locking, size limits and keepalive/cancel
- Privileged system broker `passkey-tpm-uvd` (verified core, TPM, fprintd) + unprivileged per-user agent `passkey-tpm-agent` (uhid, UI), connected over the system D-Bus (ADR-003)
- A provider D-Bus API (draft) aligned with credentialsd
- Prompts that name the relying party, through a notification or a small GTK/libadwaita prompt
- Packaging: Debian (debcargo-friendly), Fedora spec, Arch PKGBUILD; distro-neutral udev/polkit/systemd files

**Explicitly out of scope (v1):**

- Changes to the Go codebase (frozen, archived with a pointer to the new repo)
- Native messaging and the Chrome extension path (superseded by uhid plus credentialsd/portal)
- Hybrid/caBLE (phone as authenticator), which belongs to credentialsd/libwebauthn
- Syncing or exporting passkeys across machines (credentials are TPM-bound by design)
- Desktop settings panels (GNOME/KDE): roadmap M4
- Face recognition and other new biometric providers: the trait is defined, implementations come later
- FIDO Alliance certification (conformance testing only)

## Constraints

- **Technical:** Verus doesn't support async or `unsafe`, so the verified core is a pure state-machine crate. TPM access goes through the tpm2-tss C library (FFI, outside the verified core). uhid needs `/dev/uhid` access, granted by a `uaccess` udev tag rather than `plugdev`.
- **Ecosystem:** The credentialsd provider API and the xdg-desktop-portal Credentials portal (PR #1889) are not finalized, so the provider front-end has to stay swappable.
- **Distro:** Debian forbids vendoring, so prefer crates already in Debian. Crates still missing there (passkey-types, coset, ctap-types, cbor4ii) each require a NEW-queue upload.
- **License:** MIT OR Apache-2.0. The original psanford code was MIT; credit it in NOTICE.
- **Resources:** Small team, with the user as lead maintainer.

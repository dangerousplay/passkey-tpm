# Research: Rust Ecosystem & Linux Passkey Landscape

**Date:** 2026-10-03
**Sources:** crates.io API, GitHub API, sources.debian.org, Fedora mdapi, web. "Last release" = crates.io `updated_at`. UNVERIFIED items must be re-checked.

---

## 1. Crates per concern (Go equivalent → Rust)

| Concern | Go today | Recommended Rust | Version / date / license | Maturity | Notes |
|---|---|---|---|---|---|
| TPM 2.0 | go-tpm (pure Go) | `tss-esapi` | 7.7.0 (2026-04), 8.0.0-alpha.2; Apache-2.0 | High | FFI to tpm2-tss C lib (`tss-esapi-sys`). Debian sid/forky `rust-tss-esapi` 7.7.0, Fedora rawhide 7.7.0. Pure-Rust `tpm2-protocol` 1.2.0 (jarkkojs/tpm2-library) = experimental |
| CTAP2 authenticator core | hand-written `ctap2/` | `passkey-authenticator` + `passkey-types` (1Password passkey-rs) | 0.6.0 (2026-10-01); MIT/Apache; >4M dl | Med-high | `Authenticator`, `CredentialStore` trait, `UserValidationMethod` trait (docs.rs confirmed). Not in distros |
| CTAP types (alt) | — | `ctap-types` (Trussed) | 0.5.0 (2026-08); Apache/MIT | Medium | `no_std`; used by passkeyd. `fido-authenticator`/`trussed` = embedded firmware |
| CBOR | fxamacker/cbor | `ciborium` or `cbor4ii` | 0.2.2 (2024-01) / 1.2.3 (2026-09, MIT) | High / Med | **Avoid `serde_cbor`** (RUSTSEC-2021-0127). `minicbor` 2.3.0 is BlueOak-1.0.0 license (distro check). CTAP canonical ordering: passkey-types/ctap-types handle; generic crates UNVERIFIED |
| COSE | hand-written | `coset` | 0.4.2; Apache-2.0 (Google) | Med-high | Not in Debian |
| uhid | `internal/uhid` (scoped impl) | port existing code or `uhid-virt` | 0.0.8 (2025-01) | Low | Thin ecosystem; `uhid-fs`, `tokio-linux-uhid` abandoned |
| D-Bus / fprintd | godbus | `zbus` + xmlgen proxy from fprintd introspection XML | 5.19.0 (2026-08); MIT; ~90M dl | High | Pure Rust; used by credentialsd. No fprintd client crate exists |
| Crypto | x/crypto | RustCrypto `p256` 0.14 / `ecdsa` 0.17, or `aws-lc-rs` 1.18.1 | 2026 | High | `ring` 0.17.14 infrequent releases (RUSTSEC-2025-0007 withdrawn) |
| Secrets | — (GC copies) | `zeroize` 1.9 + `secrecy` 0.10.3 | | High | Key Rust advantage |
| Tray | fyne systray | `ksni` | 0.3.6; Unlicense | Medium | SNI over zbus; in Debian |
| Notifications | `desktopnotify/` | `notify-rust` | 4.18.1 | High | In Debian & Fedora |
| Native messaging | `nativemsg/` | hand-rolled (~30 LOC) or `native_messaging` 0.3.0 | | n/a | Superseded by portal long-term |
| systemd | — | `sd-notify` | 0.5.0 (Debian 0.4.1) | High | |

Client-side (NOT authenticator) libs, for reference/testing only: Mozilla `authenticator` 0.5.0, `libwebauthn` 0.10.0 (LGPL-2.1, credentialsd), `ctap-hid-fido2` 3.6.0. RP-side: kanidm `webauthn-rs` 0.5.5 (useful as test RP).

---

## 2. Linux passkey landscape (strategy-defining)

- **credentialsd / Credentials for Linux** — LGPL-3.0, Rust (zbus + tokio + libwebauthn), v0.3.1 (2026-09-07), very active. D-Bus credential service + GTK UI + Firefox/Chromium web extensions + patched Firefox Flatpak.
  - Since v0.3.0 requires patched xdg-desktop-portal; upstream PR flatpak/xdg-desktop-portal#1889 "Introduce Credentials portal (experimental)" open.
  - Packaged via OBS (Fedora/openSUSE) only.
  - Roadmap includes **TPM-backed platform authenticators**. Issue **#8** "Implement platform authenticator": separate process behind D-Bus, LSM hardening, prf/credProps/largeBlob. Issue **#26** "Design third-party password management": D-Bus `Authenticator` provider interface, opt-in registration.
  - Matrix: `#credentials-for-linux:matrix.org`.
- **passkeyd** (bjn7, Rust, GPL-3.0, 2026-02) — TPM + non-TPM, ctap-types, PAM, AUR + apt. Closest competitor.
- **Passless** (pando85, Rust, GPL-3.0) — soft-fido2 + uhid; backends pass/TPM(exp)/file. README: Flatpak/Snap/some Electron can't reach uhid. Issue #513: **Chromium ignores uhid authenticator reporting `plat: true`** for cross-platform requests → uhid cannot masquerade as platform authenticator.
- Older: psanford/tpm-fido (Go, 2024-05, our upstream lineage), bulwarkid/virtual-fido (Go, 2024-08), rust-u2f (U2F only, frozen).
- Password managers: Bitwarden/KeePassXC Linux passkeys = extension-only. No GNOME/KDE native work found beyond credentialsd outreach (UNVERIFIED).
- Login: pam-u2f, pam_fprintd, Fedora `sssd-passkey` — not WebAuthn providers.

---

## 3. Distro packaging

- **Debian:** per-crate `rust-*` via debcargo / debcargo-conf; no vendoring in official archive. Already packaged: tss-esapi, zbus, ciborium, p256, zeroize, ksni, notify-rust, webauthn-rs. **Missing:** passkey-rs, uhid-virt, coset, cbor4ii, ctap-types → each NEW-queue review. https://rust-team.pages.debian.net/book/policy.html
- **Fedora:** Rust "SHOULD NOT use bundled crates whenever possible"; `rust2rpm -V` vendored builds possible with `bundled()` Provides (wording via FOSDEM 2025 slides, page UNVERIFIED). Go vendored-by-default since F43 → Go currently easier for Fedora.
- **Arch:** either.

---

## 4. Rust vs Go for this domain

| Factor | Rust | Go |
|---|---|---|
| Secret hygiene | `zeroize`/`secrecy`, no GC copies | GC may copy; no reliable zeroization |
| TPM | tss-esapi → C tpm2-tss (packaged everywhere); pure-Rust immature | go-tpm pure Go |
| Ecosystem alignment | credentialsd, libwebauthn, passkey-rs, zbus all Rust | No Linux passkey effort in Go |
| Formal verification | Verus, Kani, hax, Aeneas, Creusot | Gobra (limited) |
| Distro | Debian easy if crates packaged; new crates add review | Fedora prefers vendored Go; Debian per-module |
| Static/reproducible | Good; tss-esapi needs dynamic tpm2-tss | Trivially static |
| Rewrite cost | High (~7.6k LOC Go) | None |

## Recommendation (from research)

Don't build another standalone uhid authenticator. Build a **credentialsd-compatible platform authenticator / provider backend in Rust** (TPM key wrapping + pluggable UV: fprintd, PIN, future), exposing a D-Bus API aligned with credentialsd #8/#26. Engage maintainers before freezing API. Keep uhid as compatibility transport (works today for browsers, libfido2, pam_u2f, systemd-cryptenroll) — noting Chromium `plat: true` limitation. Distro path: upstream into credentialsd or separate package (e.g. `credentialsd-tpm-provider`) built from already-packaged crates.

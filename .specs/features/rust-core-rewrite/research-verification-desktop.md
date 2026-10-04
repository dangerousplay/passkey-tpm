# Research: Formal Verification & Desktop/Platform Integration

**Date:** 2026-10-03
**Status:** Research input for design. Items marked UNVERIFIED must be re-checked before relying on them.

---

## A) Formal verification

### Verus (verus-lang/verus)
- Weekly dated releases; must pin Verus binary + exact `vstd` (latest seen: `vstd = "=0.0.0-2026-09-20-0158"`, Verus `0.2026.09.20.aef82ed`). Rolling builds get withdrawn — pin tagged release.
  - https://lib.rs/crates/vstd · https://github.com/verus-lang/verus-spec-check/releases/tag/verus-2026-09-27
- Toolchain: Verus on Rust 1.98 (verus#2835); verismo uses 1.98.1 = current stable → single toolchain possible. https://github.com/microsoft/verismo/pull/40
- CI tooling: `verus`, `rust_verify`, `z3`, `cargo-verus`, `verusfmt`; Bazel: https://github.com/pulseengine/rules_verus
- Verifies: requires/ensures, spec/proof/ghost code, loop invariants, termination (SMT). https://verus-lang.github.io/verus/guide/tcb.html
- Limits: Rust subset; no reasoning over classic `unsafe` (own `PPtr`/`PCell`); external crates via trusted `external_body` / `assume_specification` (unchecked → TCB). `--no-cheating` forbids assume/admit/external_body in a crate. Use edition 2021+ (verus#3003). **Async: UNVERIFIED → treat as unsupported.**
- Uses: Atmosphere microkernel (SOSP'25), Anvil (k8s controllers), verified PM log/page table (SOSP'24), VeriSMo, COCONUT-SVSM, Amazon (https://www.amazon.science/blog/developing-provably-correct-rust-code-with-verus).

### Alternatives
- **Kani** (AWS/CBMC): panic/UB freedom without annotations; contracts for unbounded proofs. Used in Firecracker, s2n-quic (+ Bolero: one harness = fuzz target + proof). https://arxiv.org/html/2607.01504v1
- **hax** (Cryspen) → F*/Lean; libcrux ML-KEM. Caveat: audit found only 58.4% of deployed code actually checked (https://eprint.iacr.org/2026/192.pdf).
- **Aeneas/Charon → Lean**: safe sequential Rust; SymCrypt PQ Rust 16.7 KLOC (https://arxiv.org/html/2609.15648v1).
- **Creusot / Prusti**: status UNVERIFIED.
- **cargo-fuzz + proptest**: mandatory baseline; differential vs OpenSK/libfido2.

### What to verify
| Component | Property | Tool |
|---|---|---|
| CBOR decoder (CTAP2 canonical subset, depth/len limits) | no panic, no OOB, bounded alloc, round-trip | Kani + cargo-fuzz + proptest |
| CTAPHID framing/reassembly | CID never reused/broadcast misuse; SEQ 0..127 in order; len ≤ max; busy/timeout/cancel; no cross-channel mixing | Verus (pure `step(state, pkt) -> (state, out)`); Kani for byte parsing |
| Credential ID wrap/unwrap | `unwrap(wrap(k, rpIdHash)) == Some(k)`; other rpIdHash → None; constant size | Verus over abstract AEAD spec + proptest |
| Sign counter | strictly monotonic, persisted before signature released, no wrap | Verus |
| UP/UV flags | UV=1 only if UV evidence in this transaction; UP=1 only after gesture; authData rpIdHash == SHA-256(rpId) | Verus, evidence as ghost/linear token required by `make_auth_data` |
| PIN protocol | retries decremented before compare; block at 0; reset only on success; per-boot 3-strike | Verus |
| Crypto | vetted crates (RustCrypto / libcrux) | don't re-verify |
| TPM / D-Bus / async glue | — | trusted shell; fuzz + integration |

**Strategy:** functional core (sync, no `unsafe`, `--no-cheating`, trusted specs isolated in one reviewed file) + imperative shell (tokio, zbus, TPM, uhid). Verus on PRs with pinned versions; Kani+Bolero for parsers; nightly fuzz; conformance via FIDO Alliance tools / `fido2-token` (availability UNVERIFIED).

---

## B) Desktop / platform integration

### authd (Entra ID / Google) and fingerprint enrollment
- authd users come from NSS module + broker snaps; local groups rewritten every login (manual `usermod` reverted). Use `extra_groups` / `owner_extra_groups` in broker.conf. https://documentation.ubuntu.com/authd/stable-docs/reference/group-management/
- Open bugs: canonical/authd **#709** (Entra user cannot use fingerprint reader), **#1610** (fingerprint option missing in GNOME Settings for authd user).
- Maintainer (libfprint/fprintd, #709): GNOME Settings hides it on purpose (externally managed user). `fprintd-enroll` as user works; real blocker = fingerprint login bypasses broker → disabled Entra account could still log in. Proposed direction: admin opt-in via `gdm-auth-config` + broker-controlled flow.
- fprintd polkit defaults: verify allow_active=yes; enroll allow_active=auth_self_keep; setusername auth_admin_keep; inactive/any=no. (LP#1532264). GNOME Settings hiding code path UNVERIFIED.
- Narrow workaround rule `/etc/polkit-1/rules.d/60-fprint-authd.rules`:
  ```js
  polkit.addRule(function(action, subject) {
    if (action.id == "net.reactivated.fprint.device.enroll" &&
        subject.local && subject.active && subject.isInGroup("fprint-users")) {
      return polkit.Result.AUTH_SELF_KEEP;   // never YES: see LP#1532264
    }
  });
  ```
  `fprint-users` via authd `extra_groups`. Never YES for `setusername`. Exclude `pam_fprintd` from `polkit-1` stack (swipe authorizing enroll; CVE-2024-37408 class).
- Proper upstream fix: broker key (e.g. `allow_local_biometrics`) via `gdm-auth-config`; pam_authd account phase revalidates with broker after fingerprint; g-c-c shows panel when policy on; broker re-auth before enroll.
- **Implication for us:** passkey use for authd users is a *distinct* concern from login: our own polkit actions (`<id>.credential.create/reset`, auth_self_keep), fprintd Verify from active session. Our enrollment UI could front `fprintd` Enroll for users g-c-c hides it from — only with admin opt-in, respecting the broker-bypass concern.

### credentialsd / Credentials for Linux
- Rust D-Bus service on libwebauthn; GTK4 credentialsd-ui; proposed xdg portal (portal = trusted caller for origin). https://github.com/linux-credentials/credentialsd · https://github.com/linux-credentials/libwebauthn
- Today: USB HID + hybrid. TPM platform authenticator, origin binding, GNOME/KDE/Flatpak = undated roadmap (FOSDEM 2026: https://alfioemanuele.io/talks/2026/02/01/fosdem-2026-credentials-for-linux.html).
- Browsers: Firefox 140+ via extension / patched Flatpak; Chrome 111+ unpacked extension; limited origins. Packaged Fedora/openSUSE (OBS). No native browser Linux platform-authenticator support found.
- No documented provider/plugin API (UNVERIFIED whether planned).
- **How we plug in:** (a) now: uhid CTAPHID — works with all browsers, libfido2, pam_u2f, credentialsd USB path; (b) medium: provider D-Bus interface / libwebauthn platform backend co-designed with linux-credentials (removes uhid + root setup). Engage early — their TPM roadmap overlaps ours.

### PAM
- pam_u2f works unchanged over hidraw: `pamu2fcfg -o pam://$HOST -i pam://$HOST`, `userverification=1`, `cue`. sudo/screen unlock fine; GDM needs daemon before login (system service + per-user storage).
- systemd-cryptenroll `--fido2-device` / systemd-homed need **hmac-secret** + UV/clientPIN options → TPM-backed hmac-secret makes us a LUKS/homed token.
- Native PAM module only for broker revalidation / skipping HID.

### Future auth methods
- libfprint/fprintd standard; secure match-on-chip enroll "coming, will take a while".
- Howdy: stable 2.6.1 (2020), 3.0 beta, issues on Ubuntu 26.04 — not production grade.
- Design: pluggable `UvProvider` trait (fprintd, PIN, future face/other); verified core consumes opaque UV-evidence token → new methods don't touch proofs.

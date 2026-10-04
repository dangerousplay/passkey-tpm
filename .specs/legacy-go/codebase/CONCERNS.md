# Codebase Concerns

**Analysis Date:** 2026-10-03

Threat-model context: this is a passkey authenticator, so a "user's process" or "local malware running as the user" counts as an adversary. The fingerprint check is meant to keep such a process from using keys without the user. Severity tags: [CRITICAL] / [HIGH] / [MEDIUM] / [LOW].

## Security Considerations

**[CRITICAL] hmac-secret / PRF output can be computed from the public credential ID:**

- Risk: `credRandom = HMAC-SHA256(seed, "credential-random")`, and `seed` is stored **in plaintext inside the credential ID** (`tpm/tpm.go:148,183-189,194-219`). The RP receives the credential ID at registration and sends it back in every `allowCredentials`. So the RP, a database leak, a network observer of the RP API, or any reader of `credentials.json` can compute every PRF/hmac-secret output offline: `HMAC(credRandom, SHA256("WebAuthn PRF"||0x00||salt))`. The TPM and the fingerprint are never involved. This defeats PRF's purpose (E2EE key derivation). It affects both HID hmac-secret (`ctap2/hmacsecret.go:106`) and native PRF-at-create (`ctap2/hmacsecret.go:178-198`, `webauthn/handler.go:230`).
- Files: `tpm/tpm.go`, `ctap2/hmacsecret.go`, `webauthn/handler.go`
- Current mitigation: none. `tpm/tpm_test.go` (`TestDeriveCredRandomMatchesHMAC`) locks in this behavior.
- Recommendations: Derive credRandom from a secret that never leaves the TPM. Options: (a) a TPM-resident HMAC key, a KEYEDHASH object under the same seed-derived primary, used via `TPM2_HMAC`; (b) a sealed per-install master secret, used as `HMAC(master, credID)`. Treat the change as breaking: existing PRF outputs change, so version the credential ID format. Also keep separate UV / non-UV credRandoms, as CTAP2.1 requires.

**[CRITICAL] TPM keys have no authorization, so fingerprint verification is only a software gate:**

- Risk: Child keys are created with `UserWithAuth` and an empty authValue, with no `authPolicy` (`tpm/tpm.go:94-115`). The parent is a primary under the Owner hierarchy with empty auth (`tpm/tpm.go:150-153,264-267`). The credential ID holds everything needed to rebuild the parent and load the key (private blob, public, seed). Any process that can open `/dev/tpmrm0` can call CreatePrimary→Load→Sign on an arbitrary challenge, with no fingerprint. The device is mode 0660 group `tss` via `tpm-udev`, and the README tells every user to join `tss`. That includes all of the user's processes **and other local users in `tss`**. Credential IDs are easy to obtain: resident ones from `~/.local/share/tpm-fido/credentials.json`, non-resident ones from the RP's login `allowCredentials` for a known username. The README claim "Private keys never leave the TPM" (`Readme.md:19`) is true, but key *use* is unrestricted.
- Files: `tpm/tpm.go`, `contrib/install-daemon.sh:50-54`, `Readme.md:96-99`
- Current mitigation: Sign is only reachable through the daemon flow, which runs `userpresence` first.
- Recommendations: Document the threat model explicitly. Bind keys to a secret that only the daemon's UID can reach: an authValue derived from a 0600 secret file or kernel keyring entry, used through `PolicyAuthValue`, or with a `PolicySecret` session. Optionally add `PolicyPCR` to bind keys to the boot state. Consider running the daemon as a dedicated system user that alone can access the TPM, with the browser-facing side unprivileged. Note that fprintd cannot be cryptographically bound to the TPM. Say so in the docs rather than implying hardware-enforced UV.

**[HIGH] Remote-triggerable panic in the hmac-secret path crashes the daemon:**

- Risk: `mode.CryptBlocks(salts, input.SaltEnc)` (`ctap2/hmacsecret.go:100-101`) panics when `len(SaltEnc)` is not a multiple of 16. The length check (32/64) only happens afterwards (`:115-133`). The client knows the ECDH shared secret, so it can produce a valid `saltAuth` for, say, 17 bytes. The CBOR worker goroutine has no `recover` (`fidohid/fidohid.go:443-446`), so the process dies. Every hidraw client can trigger this, and so can the native path if hmac input is ever wired up. systemd restarts it (`RestartSec=2`), which yields a crash loop.
- Files: `ctap2/hmacsecret.go`, `fidohid/fidohid.go`
- Recommendations: Validate `len(SaltEnc) ∈ {32,64}` and `len(SaltAuth)==16` before decrypting. Add `defer recover()` in `handleCBOR` that maps to `StatusOther`. Add fuzz tests for `HandleCommand`.

**[HIGH] Shared mutable CTAP state across HID channels (data race + cross-client assertion leak):**

- Risk: `ctap2.Handler.assertionState` and `ecdhKey` (`ctap2/ctap2.go:60,68`) are read and written without locks, while `fidohid` runs CBOR commands concurrently per channel (`fidohid/fidohid.go:397,443`). `GetNextAssertion` is not bound to the CID that issued `GetAssertion` and never expires (`ctap2/ctap2.go:226-248`). A second hidraw client can call `GetNextAssertion` and receive signed assertions plus `user.id/name/displayName` for the remaining resident credentials without any fingerprint. `GenerateECDHKey` (`ctap2/hmacsecret.go:148-156`) races with `processHmacSecret`.
- Files: `ctap2/ctap2.go`, `ctap2/getassertion.go:121-129`, `ctap2/hmacsecret.go`, `fidohid/fidohid.go`
- Recommendations: Serialize `HandleCommand` with a handler mutex, or implement CTAPHID channel locking and return `ERR_CHANNEL_BUSY` (the `errChannelBusy` constant exists but is unused, `fidohid/fidohid.go:67`). Key `assertionState` by CID, with a 30 s expiry, and clear it on any other command.

**[HIGH] Attestation uses a publicly known private key and a non-compliant, expiring certificate:**

- Risk: Every credential gets `packed` attestation signed with the GitHub SoftU2F key, which is embedded in source (`attestation/attestation.go:14-30`). Anyone can mint identical attestations. The certificate has OU=Security and no AAGUID extension (packed requires OU "Authenticator Attestation"), and it expires on **2027-07-24**. Strict RPs that verify attestation will fail, and after expiry more will. The RP's `attestation: "none"` preference is ignored in the native path (`ctap2/makecredential.go:316-331`).
- Files: `attestation/attestation.go`, `ctap2/makecredential.go:159-170,313-331`
- Recommendations: Emit `fmt: "none"` by default, or packed self-attestation signed by the credential key (no x5c). Remove the embedded private key.

**[MEDIUM] `/dev/uhid` is granted to `plugdev`:**

- Risk: `KERNEL=="uhid", MODE="0660", GROUP="plugdev"` (`contrib/90-tpm-fido-uhid.rules:2`) lets any plugdev member create arbitrary HID devices: keyboard keystroke injection into the session, or a fake FIDO device using the same VID/PID to phish prompts. `plugdev` is broad on Debian/Ubuntu and does not exist on Arch/Fedora, where udev logs an unknown group and leaves the node root-only.
- Recommendations: Use a dedicated group (e.g. `tpm-fido`) created in `postinst`, or a `TAG+="uaccess"` scoped to the active seat. Document the keystroke-injection implication.

**[MEDIUM] Fingerprint prompt does not identify the relying party:**

- Risk: HID-mode prompts are the fixed strings "FIDO2 Confirm Register" / "FIDO2 Confirm Auth" (`ctap2/makecredential.go:59`, `ctap2/getassertion.go:92`). Native mode shows a page-controlled `RP.Name` (`webauthn/handler.go:149`). The user cannot see which site they are approving, so a concurrent request from local malware on hidraw is indistinguishable.
- Recommendations: Always show the `rpId` (and user name). Keep page-supplied names secondary.

**[MEDIUM] Native Messaging origin/RP validation gaps:**

- Risk: The host trusts `envelope.Origin` as supplied by the extension (`webauthn/handler.go:50`). `validateRPID` only does a suffix match with no Public Suffix List (`webauthn/validation.go:67-73`), so `rpId: "com"`, `"co.uk"`, `"github.io"` are accepted. `crossOrigin`/`topOrigin` are fixed to false (`webauthn/clientdata.go:32`). `residentKey: "preferred"` forces a discoverable credential (`webauthn/handler.go:119`). PRF during `get` is not implemented (`webauthn/handler.go:350-356`). The manifest is pinned to the upstream extension ID (`com.vitorpy.tpmfido.json:7`).
- Recommendations: Reject public suffixes (use `golang.org/x/net/publicsuffix`). Document the extension as part of the TCB. Implement PRF-at-get once credRandom is fixed.

**[MEDIUM] Sensitive data in logs:** RP IDs, user names, full option/extension maps, and origins are logged to stderr→journal (`ctap2/makecredential.go:18-20`, `ctap2/getassertion.go:139-143,216`, `webauthn/handler.go:47,210`). This builds a browsing/account history that other users with journal access can read. Fix: gate behind a `--debug` flag.

## Known Bugs

**Documented build commands fail:**

- Symptoms: `go build ... tpmfido.go` → `undefined: autoSwitchState`, `deviceAction`.
- Trigger: `make` / `make static` / `make build` / `make static-nocgo` / `make install-daemon` (`Makefile:32,39,45`), `contrib/install-daemon.sh:74` (the Quick Start installer), the manual steps at `Readme.md:172`.
- Root cause: `auto_switch.go` (also package `main`) was added, but the targets compile a single file. The Debian build (`go build .`) works.
- Fix: build `.` everywhere. `Makefile:7` `-X main.version/buildTime` targets variables that don't exist; add them or drop the flags.

**Corrupt `credentials.json` silently wipes all resident credentials:**

- Symptoms: On a parse error, `NewCredentialStorage` logs a warning and continues empty (`ctap2/storage.go:52-56`). The next `Save` overwrites the file (`:82-95`), so every discoverable credential is lost.
- Fix: refuse to start, or move the bad file aside (`credentials.json.corrupt-<ts>`). `fsync` the temp file and directory before rename. Use a unique temp name.

**Resident-key save failure still reports success:** `ctap2/makecredential.go:110-113,271-274` continue after `storage.Save` fails. The RP believes a discoverable credential exists, but it can never be discovered. Fix: return `StatusKeyStoreFull`/error when `rk=true`.

**CTAPHID cancel and keepalive semantics:**

- `CTAPHID_CANCEL` cancels the ctx but sends no `CTAP2_ERR_KEEPALIVE_CANCEL` response (`fidohid/fidohid.go:470-476`).
- `ConfirmPresence` takes no context (`userpresence/userpresence.go:72`), so the fingerprint session keeps running for up to 30 s. Any *different* request in that window gets `OperationDenied` ("other request already in progress", `:81-84`).
- Keepalive is always `PROCESSING`, never `UPNEEDED` (`fidohid/fidohid.go:468`), so browsers don't show "touch your key" UI.
- Unsupported-algorithm returns `StatusUnsupportedExtension` (`ctap2/makecredential.go:38`) instead of `CTAP2_ERR_UNSUPPORTED_ALGORITHM` (0x26).

## Missing Critical Features (CTAP2 spec gaps)

**GetInfo over-claims FIDO_2_1:** `ctap2/getinfo.go:17` advertises `FIDO_2_1`, but `HandleCommand` (`ctap2/ctap2.go:119-133`) lacks these mandatory/expected 2.1 features:
- `authenticatorSelection` (0x0B)
- `authenticatorReset` (0x07)
- `credentialManagement` (0x0A)
- `getPinUvAuthTokenUsingUvWithPermissions`, pinUvAuthProtocol 2

ClientPIN implements only `getKeyAgreement`. Every other subcommand returns `PIN_NOT_SET` (`ctap2/ctap2.go:188-196`). `pinUvAuthParam`, `options.up`, and `options.uv` in requests are ignored. Silent (`up=false`) requests still prompt and still set UP. Not implemented: `credProtect`, `largeBlob`/`largeBlobKey`, `credBlob`, `minPinLength`, enterprise attestation. Impact: there is no way to list or delete resident credentials (only by hand-editing JSON), and no credProtect, so resident credentials are discoverable without UV policy. Fix: advertise only `FIDO_2_0`, or implement the 2.1 set, starting with Selection + credMgmt + credProtect.

**UV flag semantics:** UP|UV is set unconditionally (`ctap2/makecredential.go:135,292`, `ctap2/getassertion.go:157,228,382`). This is acceptable only because every path requires an fprintd match and there is no fallback (fail-closed when fprintd or the reader is absent, `userpresence/userpresence.go:143-148`). That is good, but it means machines without a reader cannot use the authenticator at all. fprintd "any" finger is accepted (`fprintd/fprintd.go:28`).

**Exclude-list probing without UP:** `ctap2/makecredential.go:43-52` returns `CREDENTIAL_EXCLUDED` before any user interaction, which lets any hidraw client test credential membership. CTAP2.1 requires UP first.

## Performance Bottlenecks / DoS

**Unbounded TPM work before user presence:**

- Problem: Each allowList entry, and each stored resident credential, is probed with a full CreatePrimary(ECC)+Load+Sign+2×Flush before the fingerprint prompt (`ctap2/getassertion.go:35-45,67-77`, `ctap2/getassertion.go:441`). A successful assertion then signs twice more. The device is reopened per call (`tpm/tpm.go:135,227`), and every call holds the global `TPM.mu`.
- Cause: `maxCredentialCountInList: 8` is advertised (`ctap2/getinfo.go:41`) but never enforced. CTAPHID accepts `bcnt` up to 65535 with an upfront allocation (`fidohid/fidohid.go:296-297`) against an advertised 1200 maxMsgSize. Channels are unlimited until the 30 s cleanup.
- Measurement: not measured; ECC CreatePrimary on fTPMs typically takes tens to hundreds of ms per call.
- Improvement path: enforce list limits (`CTAP2_ERR_LIMIT_EXCEEDED`), reject `bcnt > 7609` with `ERR_INVALID_LEN`, cap channels, keep one TPM connection open, and cache the seed→primary mapping per request.

## Fragile Areas

**Credential ID format (`tpm/tpm.go:183-189`, `internal/lencode`):** Encode errors are ignored. Any blob over 255 bytes (1-byte length) yields a truncated or invalid credential ID with no error. There is no version byte, so format migrations (needed for the CRITICAL fixes) cannot be distinguished. Add a version prefix and check `enc.Encode` errors.

**TPM lifecycle:** All credentials depend on the Owner-hierarchy seed. A TPM clear, fTPM reset after a BIOS/firmware update (common on AMD fTPM), or a motherboard swap irreversibly invalidates every credential. There is no backup/export story. A non-empty Owner auth (set by Windows dual-boot or tpm2-tools users) makes every CreatePrimary fail (`tpm/tpm.go:150`), with only a generic error. Document the recovery requirement (register a second authenticator). Detect `TPM_RC_BAD_AUTH` and report it clearly.

**Signature counter (`tpm/tpm.go:122-127`):** The counter is global, seconds since 2021-01-01:
- Two operations in the same second, including the MakeCredential→GetAssertion verification flow, produce equal counters, which some RPs flag as a cloned authenticator.
- A clock rollback or NTP step makes the counter decrease.
- It leaks coarse time and correlates across RPs.
- The memory backend counter is unsynchronized (`memory/memory.go:26-29`).

Fix: store a per-credential monotonic counter (e.g. in a TPM NV counter or the storage file), or return 0 consistently, which the spec allows to mean "no counter".

**Multi-process storage:** Native-mode hosts (one per browser) and the daemon each keep their own in-memory cache of the same `credentials.json`. The last writer wins, and other processes never reload. The fixed `.tmp` name collides between processes (`ctap2/storage.go:89`). The `memory` backend writes resident entries to the same file, but its keys vanish on exit (`tpmfido.go:55-60`, `memory/memory.go:20-24`). Add file locking (`flock`) with reload-on-change, and a per-backend path.

**Duplicated CTAP logic:** `MakeCredential` and `MakeCredentialDirect`, and `GetAssertion` and `GetAssertionDirect`, duplicate flag/authData/attestation code (`ctap2/makecredential.go`, `ctap2/getassertion.go`). Fixes must be applied twice. Refactor to a shared core that takes a "presence already confirmed" input.

## Platform / Distro / Vendor Assumptions

- **Debian/Ubuntu-specific:**
  - `debian/control` depends on `tpm-udev` (provides the `tss` group).
  - The changelog targets `resolute` (26.04).
  - The udev rule invokes `/usr/lib/snapd/snap-device-helper` and snap tags (`contrib/90-tpm-fido-uhid.rules:10-15`).
  - The `plugdev` group.
  - `gnome-shell-extension-appindicator` is a Recommends.
  - Fedora/Arch need a different group setup and no snap rules.
- **Yubico-only auto-switch:** VID `1050` is hardcoded (`tpmfido.go:269`). Nitrokey, SoloKeys, Feitian, Google Titan, and Token2 are not detected. Polling is USB-only and every 2 s (`usbmon/usbmon.go`). Make it a list or flag, or detect any hidraw with `ID_FIDO_TOKEN=1` that isn't ours (via udev netlink).
- **Hardcoded HID identity:** VID 0x1209 / PID 0xF1D0 and `Bus: 3` (USB), set in `fidohid/fidohid.go:135`. Verify the pid.codes allocation, and make it configurable.
- **Native-messaging install paths** cover only Google Chrome/Chromium config dirs (`Makefile:56-59`, `contrib/install.sh:25-34`). They miss Brave, Edge, Vivaldi, and Flatpak.
- **ThinkPad:** there are **no ThinkPad-specific code paths**. The name and `Readme.md` tested hardware are the only ties.
- **Already hardware/vendor-agnostic:**
  - The TPM goes through the kernel RM `/dev/tpmrm0`, so Intel PTT, AMD fTPM, and discrete TPMs all work.
  - fprintd/libfprint covers any supported reader.
  - UHID is generic kernel.
  - hidraw ACLs come from systemd's `fido_id` + `uaccess`.
  - D-Bus notifications/tray are desktop-agnostic, with no GNOME API used directly.
  - `CGO_ENABLED=0` static build; CI cross-builds 386/arm.

## Dependencies at Risk

**Supply chain of installers:** `scripts/install-latest.sh:3,16,36` is a `curl | bash` of releases from the upstream `vitorpy/tpm-fido2-prf`, with no checksum or signature verification. The `.deb` build runs `go mod vendor` with network access inside the container (`packaging/docker/build-in-container.sh`), so it is not hermetic. Fix: point to this fork, publish SHA256SUMS plus signatures, and commit or verify the vendor hash.

**`go-tpm-tools` pseudo-version (2023)** is only for the simulator tests (`go.mod`). Low runtime risk, but it pins cgo/OpenSSL for CI.

## Test Coverage Gaps

**`ctap2` has 0% coverage (no test file):** MakeCredential/GetAssertion/GetNextAssertion, the hmac-secret crypto, authData encoding, storage, and GetInfo are all untested. Risk: every bug above is in this package. Priority: High. Difficulty: low. A `memory` backend plus a fake `userpresence` verifier is enough. Add test vectors from the CTAP2 spec for hmac-secret, plus `go test -fuzz` targets for CBOR request parsing and `fidohid.handleOutput`.

**`webauthn.Handler` flows (10.5%):** create/get paths, PRF-at-create, and error mapping are untested. Priority: High.

**`memory` and `usbmon` (0%), `tray` (7%):** Priority: Low/Medium.

**No conformance testing:** nothing runs the FIDO Conformance Tools, `libfido2` (`fido2-token -I`, `fido2-assert`), or a browser against the UHID device. Priority: Medium. Use the `uhid` build-tag harness with `libfido2` in CI on a VM with `/dev/uhid`.

**Lint/format not enforced:** `gofmt -l` flags 8 files (`ctap2/*`, `webauthn/{errors,types}.go`). No golangci-lint/govulncheck in CI.

---

_Concerns audit: 2026-10-03_
_Update as issues are fixed or new ones discovered_

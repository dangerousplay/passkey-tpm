# Tech Stack

**Analyzed:** 2026-10-03

## Core

- Language: Go, `go 1.25.0` (`go.mod`); CI matrix `1.25.x` + `stable` (`.github/workflows/go.yml`)
- Module path: `github.com/moritzheiber/tpm-fido2-thinkpad-linux` (fork of vitorpy/tpm-fido2-prf, itself derived from psanford/tpm-fido)
- Runtime: single static binary (`CGO_ENABLED=0`), Linux only (uses `/dev/uhid`, `/dev/tpmrm0`, sysfs, D-Bus)
- Package manager: Go modules; `vendor/` generated at Debian build time only (gitignored, `debian/rules` uses `-mod=vendor`)
- Size: ~7.6k LOC Go incl. tests, 16 packages

## Direct Dependencies (`go.mod`)

| Module | Version | Used for |
| --- | --- | --- |
| `github.com/google/go-tpm` | v0.9.8 | TPM 2.0 commands via `tpm2` + `transport/linuxtpm` (`tpm/tpm.go`) |
| `github.com/fxamacker/cbor/v2` | v2.9.3 | CTAP2 CBOR encode/decode (canonical enc mode in `ctap2/ctap2.go:137`) |
| `github.com/godbus/dbus/v5` | v5.2.2 | fprintd (system bus) and desktop notifications (session bus) |
| `fyne.io/systray` | v1.12.2 | StatusNotifierItem tray icon (pure Go) |
| `golang.org/x/crypto` | v0.55.0 | `hkdf`, `cryptobyte`, `chacha20poly1305` (memory backend) |
| `golang.org/x/sys` | v0.47.0 | `unix` constants for UHID |

Indirect: `github.com/google/go-tpm-tools` (2023 pseudo-version, only the cgo TPM simulator used under `tpmsim` tag), `github.com/x448/float16`.

## Domain Protocols Implemented In-Repo

- CTAP2 (subset): `ctap2/` — MakeCredential, GetAssertion, GetNextAssertion, GetInfo, ClientPIN(getKeyAgreement only), hmac-secret
- CTAPHID framing over UHID: `fidohid/` + `internal/uhid/` (hand-written UHID ABI, replaced external lib in commit cfc5be8)
- WebAuthn JSON over Chrome Native Messaging: `webauthn/`, `nativemsg/`
- Attestation: `packed` with embedded SoftU2F self-signed cert (`attestation/`)

## Testing

- Unit: Go `testing` stdlib only (no testify/mocks lib); hand-written fakes via interfaces
- Integration (opt-in build tags): `tpmsim` (go-tpm-tools simulator, needs cgo + libssl-dev), `uhid` (real `/dev/uhid`), `fingerprint` (live fprintd), `desktop` (live notification daemon)
- E2E: none automated; `test_native_msg.py` is a manual Native Messaging driver

## External Services (local system services, no network)

- TPM 2.0 resource manager: `/dev/tpmrm0`
- fprintd: `net.reactivated.Fprint` on system D-Bus
- Desktop notifications: `org.freedesktop.Notifications` on session D-Bus
- Tray host: StatusNotifierItem (GNOME needs `gnome-shell-extension-appindicator`)
- Kernel: `uhid` module, hidraw, sysfs `/sys/bus/usb/devices`

## Development / Build Tools

- Make: `Makefile` (musl static, nocgo, dist tarballs) — note single-file build targets are broken, see CONCERNS.md
- Debian packaging: `debian/` (debhelper-compat 13, targets Ubuntu 26.04 "resolute"), built in Docker via `packaging/build-deb.sh` + `packaging/docker/Dockerfile` (`ubuntu:26.04`)
- Installers: `contrib/install-daemon.sh` (HID daemon), `contrib/install.sh` (native messaging), `scripts/*-template.sh` (dist tarball)
- CI: GitHub Actions `go.yml` (build, `-race` tests, tpmsim, GOARCH=386 tests, GOARCH=arm build)
- Dependabot: gomod, github-actions, docker (weekly, grouped)
- Lint: none configured (no golangci-lint); `go vet` passes clean

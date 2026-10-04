# Project Structure

**Root:** `tpm-fido2-thinkpad-linux` (legacy Go repository)

## Directory Tree

```
.
├── tpmfido.go              # main: flags, wiring, native/daemon/tray modes
├── auto_switch.go          # pure YubiKey auto-switch state machine (main pkg)
├── tpmfido_test.go, auto_switch_test.go
├── ctap2/                  # CTAP2 core: commands, types, authData, hmac-secret, storage
├── fidohid/                # CTAPHID framing over virtual HID
├── internal/
│   ├── uhid/               # Linux /dev/uhid ABI (create2/input2/output events)
│   └── lencode/            # 1-byte length-prefixed record encoding (credential IDs)
├── tpm/                    # TPM 2.0 signer backend (go-tpm)
├── memory/                 # in-process signer backend (testing)
├── attestation/            # embedded SoftU2F attestation cert + key
├── userpresence/           # fingerprint-gated presence orchestration
├── fprintd/                # fprintd D-Bus client
├── desktopnotify/          # org.freedesktop.Notifications client
├── tray/                   # systray UI (+ icons/active.png, inactive.png)
├── usbmon/                 # sysfs USB vendor polling
├── webauthn/               # WebAuthn JSON handler for Native Messaging
├── nativemsg/              # Chrome Native Messaging framing
├── contrib/                # udev rule, modules-load, user service, installers
├── debian/                 # Debian/Ubuntu 26.04 packaging
├── packaging/              # build-deb.sh + docker/ (Dockerfile, build-in-container.sh)
├── scripts/                # dist-tarball install/update/uninstall/test templates
├── docs/EXTENSION_PROTOCOL.md
├── com.vitorpy.tpmfido.json  # Native Messaging host manifest template
├── test_native_msg.py      # manual native messaging driver
├── Makefile, Readme.md, LICENSE, go.mod, go.sum
└── .github/ (workflows/go.yml, dependabot.yml)
```

## Module Organization

### CTAP2 core
**Purpose:** Authenticator logic independent of transport.
**Location:** `ctap2/`
**Key files:** `ctap2.go` (Handler, dispatch, ClientPIN, GetNextAssertion), `makecredential.go`, `getassertion.go`, `getinfo.go`, `hmacsecret.go`, `storage.go` (resident-key JSON store), `authenticatordata.go`, `types.go`, `commands.go`.

### HID transport
**Purpose:** Expose authenticator as USB-like FIDO HID device.
**Location:** `fidohid/`, `internal/uhid/`
**Key files:** `fidohid/fidohid.go` (VID 0x1209 / PID 0xF1D0, report descriptor, channel state), `internal/uhid/uhid.go`.

### Native Messaging transport
**Purpose:** Platform-authenticator mode for the companion Chrome extension (separate repo).
**Location:** `webauthn/`, `nativemsg/`, `com.vitorpy.tpmfido.json`, `docs/EXTENSION_PROTOCOL.md`.

### Key backends
**Purpose:** Key generation/signing and credRandom derivation behind `ctap2.Signer`.
**Location:** `tpm/tpm.go`, `memory/memory.go`, `internal/lencode/`.

### User interaction
**Purpose:** Fingerprint-based presence, notifications, tray.
**Location:** `userpresence/`, `fprintd/`, `desktopnotify/`, `tray/`, `usbmon/`, `auto_switch.go`.

## Where Things Live

**Credential creation / assertion:**
- Interface: `fidohid/fidohid.go` (HID) or `webauthn/handler.go` (native)
- Business logic: `ctap2/makecredential.go`, `ctap2/getassertion.go`
- Key material: `tpm/tpm.go`
- Data persistence: `ctap2/storage.go` -> `~/.local/share/tpm-fido/credentials.json` (path set in `tpmfido.go:74`)

**User verification:**
- UI: `desktopnotify/`, prompt strings in `ctap2/*.go` and `webauthn/handler.go`
- Logic: `userpresence/userpresence.go`
- Driver: `fprintd/fprintd.go`

**Device enable/disable:**
- UI: `tray/tray.go`
- Logic: `auto_switch.go`, `tpmfido.go:147-296`
- Detection: `usbmon/usbmon.go`

**System integration / configuration:**
- udev: `contrib/90-tpm-fido-uhid.rules`
- kernel module: `contrib/uhid.conf`
- systemd user units: `contrib/tpm-fido.service` (`%h/bin`), `debian/tpm-fido.user.service` (`/usr/bin`, resource limits)
- CLI flags: `tpmfido.go:27-33`

## Special Directories

**`debian/`:** Native package for Ubuntu 26.04: `control` (Depends fprintd, tpm-udev, kmod, udev), `rules` (vendored static build, runs `go test ./...`), `tpm-fido.install`, `postinst`/`postrm` (udev reload, modprobe), `tpm-fido.1` man page, lintian overrides.

**`packaging/`:** Reproducible container build of the `.deb` (`build-deb.sh` -> `docker/build-in-container.sh`, runs `go mod vendor` with network).

**`scripts/`:** Templates copied into `make dist-complete` tarballs; `install-latest.sh` pulls releases from the upstream `vitorpy/tpm-fido2-prf` repo.

**`contrib/`:** Source-install path (home-dir binary, `/etc/udev/rules.d`).

**`.specs/`:** Planning/spec docs (this mapping).

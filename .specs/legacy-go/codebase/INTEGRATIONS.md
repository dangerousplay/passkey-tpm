# External Integrations

All integrations are local OS services or kernel interfaces; the daemon makes no network calls.

## Key Storage / Crypto Hardware

**Service:** TPM 2.0 via kernel resource manager
**Purpose:** Generate and use per-credential ECDSA P-256 keys.
**Implementation:** `tpm/tpm.go` using `github.com/google/go-tpm` `tpm2` API + `transport/linuxtpm`. A new device handle is opened per operation (`tpm.go:33-35, 135, 227`) and serialized by `TPM.mu`.
**Configuration:** `--device` flag, default `/dev/tpmrm0` (`tpmfido.go:29`); `--backend tpm|memory`.
**Authentication:** Unix permissions on `/dev/tpmrm0` (group `tss`, provided by Debian `tpm-udev`); TPM Owner hierarchy used with empty auth (`tpm.go:150-153, 264-267`); child key has no authValue and no policy (`tpm.go:94-115`).
**Commands used:** `CreatePrimary` (Owner, ECC P-256 restricted decrypt, Unique = HKDF(seed, rpIdHash)), `Create`, `Load`, `Sign` (ECDSA-SHA256, null-hierarchy ticket), `FlushContext`. No NV, no PCR, no sessions.

## Fingerprint Verification

**Service:** fprintd (`net.reactivated.Fprint`, system D-Bus)
**Purpose:** User verification gate before every MakeCredential/GetAssertion.
**Implementation:** `fprintd/fprintd.go`; orchestrated by `userpresence/userpresence.go`.
**Configuration:** none; uses `Manager.GetDefaultDevice`.
**Authentication:** fprintd's polkit policy (`net.reactivated.fprint.device.verify`) for the calling user's session; `Claim("")` = calling user.
**Key calls:** `Manager.GetDefaultDevice`, `Device.Claim`, `VerifyStart("any")`, signal `VerifyStatus`, `VerifyStop`, `Release`. Non-match restarts; `verify-disconnected` / `verify-unknown-error` are fatal; unknown results treated as transient (`fprintd.go:52-73`).

## Desktop Notifications

**Service:** `org.freedesktop.Notifications` (session D-Bus)
**Purpose:** Prompt "Touch fingerprint sensor" and retry hints; one replaceable notification per request, 30 s expiry.
**Implementation:** `desktopnotify/desktopnotify.go`; failures are non-fatal (`userpresence.go:129-141`).

## System Tray

**Service:** StatusNotifierItem host (GNOME via `gnome-shell-extension-appindicator`, KDE native)
**Purpose:** Toggle virtual device, auto-switch checkbox, YubiKey status, Quit.
**Implementation:** `tray/tray.go` with `fyne.io/systray`; icons embedded via `//go:embed`.
**Configuration:** `--tray`, `--auto-switch` flags.

## Kernel Interfaces

### UHID (virtual HID device)
**Purpose:** Present a FIDO2 HID device (usage page 0xF1D0) to all browsers.
**Location:** `internal/uhid/uhid.go` (UHID_CREATE2/INPUT2/OUTPUT, EIO replies to GET/SET_REPORT), `fidohid/fidohid.go:132-148` (name `tpm-fido`, Bus 3 = BUS_USB, VID 0x1209, PID 0xF1D0).
**Authentication:** `/dev/uhid` mode 0660 group `plugdev` (`contrib/90-tpm-fido-uhid.rules:2`). Resulting `/dev/hidrawN` access is not set by this repo; relies on systemd's `fido_id` udev builtin (`ID_FIDO_TOKEN=1`) + `uaccess` for the active seat user.
**Module load:** `contrib/uhid.conf` -> `/usr/lib/modules-load.d` (deb) or `/etc/modules-load.d` (installer); `postinst` runs `modprobe uhid`.

### sysfs USB polling
**Purpose:** Detect a physical YubiKey to auto-disable the virtual key.
**Location:** `usbmon/usbmon.go` globbing `/sys/bus/usb/devices/*/idVendor` every 2 s; vendor hardcoded `1050` at `tpmfido.go:269`.

### Snap confinement
**Purpose:** Let Chromium/Firefox snaps open the virtual hidraw node.
**Location:** `contrib/90-tpm-fido-uhid.rules:10-15` tags `snap_chromium_chromium` / `snap_firefox_firefox` and runs `/usr/lib/snapd/snap-device-helper`; installer runs `snap connect <browser>:u2f-devices`.

## API Integrations

### Chrome Native Messaging (companion extension)
**Purpose:** Platform-authenticator mode with WebAuthn PRF during create.
**Location:** `tpmfido.go:96-104, 319-347`, `nativemsg/io.go` (4-byte LE length, max 1 MiB), `webauthn/handler.go`, spec in `docs/EXTENSION_PROTOCOL.md`.
**Authentication:** Browser enforces `allowed_origins: chrome-extension://bfmfknknibchmioeamgbnlpakcjimnbf/` (`com.vitorpy.tpmfido.json`); host trusts the `origin` field supplied by the extension, then validates https + rpId suffix (`webauthn/validation.go`).
**Key messages:** `{type: "create"|"get", requestId, origin, options}` -> `CreateResponse` / `GetResponse` / error with DOMException name.
**Install:** manifest copied to `~/.config/{google-chrome,chromium}/NativeMessagingHosts/` with `__HOME__` substitution (`Makefile:56-59`, `contrib/install.sh`). Not installed by the `.deb`.

### Browser CTAP2 clients (HID mode)
**Purpose:** Any CTAP2 client (Chrome, Firefox, libfido2, ssh-keygen -t ecdsa-sk, systemd-cryptenroll) can talk to the device.
**Advertised capabilities:** `ctap2/getinfo.go` — versions FIDO_2_0/FIDO_2_1, extension `hmac-secret`, options rk/up/uv=true, plat per mode, pinUvAuthProtocols [1], maxMsgSize 1200, AAGUID = SHA256("tpm-fido-prf")[:16].

## Persistence

**Resident credential metadata:** JSON array at `~/.local/share/tpm-fido/credentials.json` (dir 0700, file 0600, atomic rename) — `ctap2/storage.go`, path fixed in `tpmfido.go:74`. Fields: rp_id, rp_name, user_id, user_name, user_display_name, credential_id, public key, created_at.

## Service Management

**Background process:** systemd **user** service, `--mode=daemon --tray`:
- `contrib/tpm-fido.service` (`%h/bin/tpm-fido`, Restart=on-failure)
- `debian/tpm-fido.user.service` (`/usr/bin/tpm-fido`, MemoryMax=128M, TasksMax=64, LimitNOFILE=256), installed `--no-enable`.
**Queue system / webhooks:** none.

## Distribution Channels

- `.deb` for Ubuntu 26.04 built in Docker (`packaging/`).
- Source installers (`contrib/install-daemon.sh`, `contrib/install.sh`).
- Release tarballs (`make dist`, `make dist-complete` which copies `../tpm-fido2-extension`), and `scripts/install-latest.sh` which downloads from the upstream `vitorpy/tpm-fido2-prf` GitHub releases.

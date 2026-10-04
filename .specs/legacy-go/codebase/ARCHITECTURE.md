# Architecture

**Pattern:** Single-binary modular monolith (one `main` package + focused library packages), two front-end transports sharing one CTAP2 core and one pluggable signer backend.

## High-Level Structure

```
            Browser (any)                         Chrome + companion extension
                 |  /dev/hidrawN (FIDO usage page 0xF1D0)        |  stdin/stdout (4-byte LE len + JSON)
          kernel HID <-> /dev/uhid                               |
                 |                                               |
   [--mode=daemon]  fidohid.Device (CTAPHID)        [--mode=native] nativemsg + webauthn.Handler
                 |  HandleCommand(cmd, cbor)                     |  MakeCredentialDirect / GetAssertionDirect
                 +-----------------> ctap2.Handler <-------------+
                                      |    |     |
             userpresence.UserPresence    |   ctap2.CredentialStorage (~/.local/share/tpm-fido/credentials.json)
               |            |             |
        fprintd (sysbus)  desktopnotify   ctap2.Signer interface
                          (sessionbus)        |-- tpm.TPM   (/dev/tpmrm0, default)
                                              `-- memory.Mem (in-process, testing)
   daemon+tray only: tray.Tray (systray) + usbmon.Monitor (sysfs poll, Yubico VID 1050) + autoSwitchState (auto_switch.go)
```

Entry point: `tpmfido.go` `main()` parses flags (`--backend`, `--device`, `--mode`, `--tray`, `--auto-switch`), builds signer, `userpresence.New()`, `ctap2.NewCredentialStorage`, `ctap2.NewHandler`, then dispatches to `runNativeMode` or `runDaemonMode` (`runDaemonHeadless` / `runDaemonWithTray`).

## Identified Patterns

### Interface-at-consumer for hardware seams

**Location:** `ctap2/ctap2.go:16` (`Signer`), `fidohid/fidohid.go:91` (`CommandHandler`), `fidohid/fidohid.go:125` (`hidTransport`), `userpresence/userpresence.go:18,24` (`Verifier`, `Notifier`), `fprintd/fprintd.go:77` (`verifySession`), `internal/uhid/uhid.go:51` (`deviceFile`), `desktopnotify` `service`.
**Purpose:** Swap TPM/fprintd/D-Bus/UHID for fakes in unit tests and allow `memory` backend.
**Implementation:** Small interfaces declared in the consuming package; constructor fields (`newVerifier`, `newNotifier`, `open`) overridden by tests in the same package.

### Stateless wrapped-key credentials

**Location:** `tpm/tpm.go:131-190`, `tpm/tpm.go:239-319`.
**Purpose:** No per-credential TPM NV/persistent handles; credential ID carries everything needed to reload the key.
**Implementation:** Per credential: random 20-byte seed -> HKDF(seed, "tpm-fido-application-key"||rpIdHash) forms the `Unique` of an ECC P-256 restricted storage primary under the Owner hierarchy; a child ECDSA key is `Create`d under it. Credential ID = lencode(`TPM`-separated, 1-byte length) of `[OutPrivate, TPMTPublic, seed]`. Signing recreates the primary, `Load`s the child, `Sign`s, flushes both. RP binding comes from rpIdHash in the primary template (wrong RP => Load fails).

### Signer probing as credential lookup

**Location:** `ctap2/getassertion.go:35-45, 67-77, 322-330, 350-361`, `ctap2/makecredential.go:43-52, 238-247`.
**Purpose:** Decide whether a credential ID belongs to this authenticator + RP.
**Implementation:** Calls `SignASN1` on a fixed dummy digest; success = "credential valid". Every probe is a full TPM CreatePrimary/Load/Sign cycle.

### Fan-in user-presence requests

**Location:** `userpresence/userpresence.go:72-200`.
**Purpose:** Browsers retry identical requests; avoid multiple fingerprint prompts.
**Implementation:** One `activeRequest` keyed by (clientDataHash, rpIdHash). Identical requests append a waiter and extend the timeout; different concurrent requests are rejected. A goroutine shows a replaceable notification, runs `fprintd.Verify` ("any" finger, retries non-match), and broadcasts `Result` to waiters.

### Context-driven lifecycle with worker WaitGroup

**Location:** `fidohid/fidohid.go:152-225`, `internal/uhid/uhid.go:134-205`, `tpmfido.go:147-296`.
**Purpose:** Clean start/stop of the virtual device (tray toggle, YubiKey auto-switch, SIGTERM).
**Implementation:** `Device.Run(ctx)` owns transport; read loop uses deadline-based cancellation (`context.AfterFunc` + `SetReadDeadline`); CBOR commands run in `d.workers.Go`; teardown cancels channels, closes UHID, waits workers. Tray mode guards start/stop with a mutex and a pure state machine (`auto_switch.go`).

### Two parallel CTAP2 entry styles

**Location:** `ctap2/makecredential.go:17` vs `:226`, `ctap2/getassertion.go:13` vs `:303`.
**Purpose:** HID path needs full CBOR request/response with UP inside; native path does UP in `webauthn/handler.go` and calls `*Direct` methods returning Go structs.
**Implementation:** Largely duplicated logic (flags, authData, attestation) in both variants.

## Data Flow

### Registration over HID (daemon mode)

1. Browser writes 64-byte reports to hidraw -> kernel -> UHID `Output` event (`internal/uhid/uhid.go:187`).
2. `fidohid.handleOutput` strips report ID, assembles init/cont packets per CID (`fidohid.go:228-353`).
3. `CTAPHID_CBOR` -> worker goroutine `handleCBOR` sends KEEPALIVE every 100 ms and calls `ctap2.Handler.HandleCommand` (`fidohid.go:410-479`).
4. `MakeCredential`: validate clientDataHash/ES256, probe excludeList, `ConfirmPresence` (fingerprint), `RegisterKey` in TPM, optionally persist resident metadata, build authData (flags UP|UV|AT[|ED]), sign `packed` attestation with the embedded SoftU2F key (`makecredential.go:17-187`).
5. Response fragmented into reports via UHID `INPUT2` (`fidohid.go:482-514`).

### Authentication over HID

1. `GetAssertion`: if allowList, probe each ID until one signs; else load resident creds for rpId from storage and probe each (`getassertion.go:13-85`).
2. Fingerprint via `ConfirmPresence`; on success build authData (UP|UV, counter = seconds since 2021-01-01), optional hmac-secret (ECDH with handler-wide ephemeral key, protocol 1), TPM sign (`getassertion.go:136-281`).
3. Multiple resident creds -> `assertionState` stored on the handler for `GetNextAssertion` (`ctap2.go:226-248`).

### Native Messaging (extension) mode

1. `runNativeMessaging` loop reads length-prefixed JSON from stdin (`tpmfido.go:319-347`, `nativemsg/io.go`).
2. `webauthn.Handler.HandleRequest` validates origin is https and rpId is a suffix of origin host (`webauthn/validation.go`), builds `clientDataJSON` itself, runs `ConfirmPresence`, then `MakeCredentialDirect`/`GetAssertionDirect`; PRF computed directly at create via `ComputePRF` (`webauthn/handler.go:201-245`). PRF at get is not implemented (`handler.go:350-356`).

### Tray / auto-switch

`usbmon.Monitor` polls `/sys/bus/usb/devices/*/idVendor` every 2 s for `1050`; transitions through `autoSwitchState` start/stop the `fidohid.Device` (`tpmfido.go:205-289`).

## Code Organization

**Approach:** Layer/capability-based packages, flat at repo root.

**Module boundaries:**
- Transport: `fidohid`, `internal/uhid`, `nativemsg`
- Protocol/domain: `ctap2` (CTAP2 + storage), `webauthn` (WebAuthn JSON facade over ctap2)
- Crypto backends: `tpm`, `memory`, `attestation`, `internal/lencode`
- User interaction: `userpresence`, `fprintd`, `desktopnotify`, `tray`
- Platform glue: `usbmon`, `main` (`tpmfido.go`, `auto_switch.go`)

Dependency direction: `main` -> everything; `webauthn` -> `ctap2` -> `userpresence`, `attestation`; `userpresence` -> `fprintd`, `desktopnotify`; `fidohid` -> `internal/uhid`; `tpm` -> `internal/lencode`. No cycles. `ctap2.Handler` is a single shared mutable object used concurrently by the HID workers.

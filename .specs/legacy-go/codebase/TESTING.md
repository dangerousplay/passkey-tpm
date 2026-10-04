# Testing Infrastructure

## Test Frameworks

**Unit/Integration:** Go stdlib `testing` (Go 1.25+), no assertion or mocking library.
**E2E:** None automated. `test_native_msg.py` is a manual script that spawns the binary and exchanges Native Messaging frames.
**Coverage:** `go test -cover` (not enforced, no CI reporting).

## Test Organization

**Location:** Co-located `_test.go` files in the same package (white-box; tests access unexported fields such as `newVerifier`, `open`, `requestTimeout`).
**Naming:** `TestXxx` descriptive behavior names (`TestIdenticalRequestExtendsTimeout`, `TestCloseWaitsForCommandWorkers`). Live/hardware tests carry a suffix and a build tag.
**Structure:** Mostly table-free single-scenario tests; a few table tests (`fprintd TestClassifyResult`, `webauthn TestValidateRPID`, `TestValidateOrigin`).

| Build tag | Files | Needs |
| --- | --- | --- |
| (none) | most `_test.go` | nothing (`internal/uhid/uhid_test.go` is `//go:build linux`, uses fake file) |
| `tpmsim` | `tpm/tpm_sim_test.go` | cgo, C toolchain, `libssl-dev` (go-tpm-tools simulator) |
| `uhid` | `fidohid/uhid_integration_test.go` | `/dev/uhid` access, daemon stopped |
| `fingerprint` | `fprintd/fprintd_live_test.go` | fprintd + enrolled finger + human touch |
| `desktop` | `desktopnotify/desktopnotify_live_test.go` | session notification daemon |

## Testing Patterns

### Unit Tests

**Approach:** Interface fakes injected by overriding constructor fields or passing fakes to unexported functions. Examples: fake `Verifier`/`Notifier` in `userpresence/userpresence_test.go`; fake `verifySession` in `fprintd/fprintd_test.go`; fake `hidTransport` in `fidohid/lifecycle_test.go`; fake `deviceFile` asserting exact UHID wire bytes in `internal/uhid/uhid_test.go`; fake D-Bus `service` in `desktopnotify`. Pure state machine tests for `auto_switch.go`.
**Location:** alongside source.

### Integration Tests

**Approach:** Opt-in via build tags against real kernel/TPM-simulator. `tpm_sim_test.go` drives `registerKey`/`signASN1` through `simulator.Get()` and verifies ECDSA with `crypto/ecdsa`, rejects foreign-RP handle, checks credRandom stability. `uhid_integration_test.go` creates real virtual devices and round-trips CTAPHID.
**Location:** `tpm/`, `fidohid/`.

### E2E Tests

None. No test drives a browser or `libfido2` (`fido2-token`, `fido2-cred`) against the virtual device.

## Test Execution

**Commands (from Readme.md, Makefile, CI):**
- `go test ./...` (default; also `make test` = `go test -v ./...`; Debian `override_dh_auto_test`)
- `go test -race -v ./... --timeout 60s` (CI)
- `go test -tags tpmsim -v ./tpm/... --timeout 120s` (CI, needs libssl-dev)
- `env GOOS=linux GOARCH=386 go test -v ./... --timeout 60s` (CI)
- `go test -race -tags uhid ./fidohid` (manual)
- `go test -tags fingerprint -run TestLiveAnyFinger -v ./fprintd` (manual)
**Configuration:** none beyond build tags.

## Coverage Targets

**Current (measured 2026-10-03, `go test -cover ./...`, default tags):**
`attestation` 94.7%, `internal/lencode` 89.7%, `internal/uhid` 88.1%, `userpresence` 87.6%, `nativemsg` 72.7%, `desktopnotify` 58.8%, `fidohid` 45.4%, `fprintd` 40.4%, `tpm` 16.8% (more with `tpmsim`), `main` 12.2%, `webauthn` 10.5%, `tray` 7.3%, **`ctap2` 0.0% (no test file)**, `memory` 0.0%, `usbmon` 0.0%.
**Goals:** none documented.
**Enforcement:** none.

Total: 91 tests pass across 15 packages (default tags).

## Test Coverage Matrix

| Code Layer | Required Test Type | Location Pattern | Run Command |
| --- | --- | --- | --- |
| CTAP2 command logic (`ctap2/`) | unit with `memory` backend + fake presence (currently **none**) | `ctap2/*_test.go` | `go test ./ctap2/...` |
| CBOR parsing / hmac-secret | unit + fuzz (currently **none**) | `ctap2/*_test.go` (`FuzzXxx`) | `go test -fuzz=FuzzXxx ./ctap2` |
| TPM backend | unit (templates) + integration (simulator) | `tpm/tpm_test.go`, `tpm/tpm_sim_test.go` | `go test ./tpm/... && go test -tags tpmsim ./tpm/...` |
| CTAPHID framing | unit with fake transport + opt-in uhid integration | `fidohid/*_test.go` | `go test -race ./fidohid` / `-tags uhid` |
| UHID ABI | unit (fake fd) | `internal/uhid/uhid_test.go` | `go test ./internal/uhid` |
| User presence / fprintd | unit with fakes; live opt-in | `userpresence/*_test.go`, `fprintd/*_test.go` | `go test ./userpresence ./fprintd` |
| WebAuthn native handler | unit (validation, clientData only; handler flows **untested**) | `webauthn/*_test.go` | `go test ./webauthn` |
| Native messaging framing | unit | `nativemsg/io_test.go` | `go test ./nativemsg` |
| Tray / usbmon | unit (tray state only); usbmon **none** | `tray/tray_test.go` | `go test ./tray` |
| main wiring / auto-switch | unit (state machine) | `auto_switch_test.go`, `tpmfido_test.go` | `go test .` |
| Packaging / udev / installers | none | — | — |

## Parallelism Assessment

| Test Type | Parallel-Safe? | Isolation Model | Evidence |
| --- | --- | --- | --- |
| Default unit tests | Yes (across packages); no `t.Parallel()` used within packages | All hardware behind per-test fakes; no shared files or globals mutated | `userpresence_test.go`, `fidohid/lifecycle_test.go`, `uhid_test.go` construct fresh fakes |
| `tpmsim` | Yes per package | In-process simulator per test | `tpm/tpm_sim_test.go` |
| `uhid` integration | No | Creates real system-wide virtual HID devices with fixed VID/PID; conflicts with running daemon | Readme "should run with the daemon stopped" |
| `fingerprint` / `desktop` live | No | Real system services, human interaction | build tags |

## Gate Check Commands

| Gate Level | When to Use | Command |
| --- | --- | --- |
| Quick | After tasks with unit tests only | `go test ./...` |
| Full | After tasks touching TPM/HID/concurrency | `go test -race ./... --timeout 60s && go test -tags tpmsim ./tpm/... --timeout 120s` |
| Build | After phase completion | `go vet ./... && go build ./... && go test -race ./... && go test -tags tpmsim ./tpm/... && GOOS=linux GOARCH=386 go test ./...` |

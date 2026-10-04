# Code Conventions

## Naming Conventions

**Files:**
Lowercase, no separators, named after the package or the CTAP command they implement; tests are `<name>_test.go`, hardware/live tests use `<name>_live_test.go`, `_sim_test.go`, `_integration_test.go`. One exception uses snake case (`auto_switch.go`).
Examples: `ctap2/makecredential.go`, `ctap2/getassertion.go`, `ctap2/hmacsecret.go`, `fprintd/fprintd_live_test.go`, `tpm/tpm_sim_test.go`, `fidohid/uhid_integration_test.go`.

**Packages:** short lowercase single word matching the directory (`ctap2`, `fidohid`, `userpresence`, `desktopnotify`, `lencode`).

**Functions/Methods:**
Exported PascalCase for API, lowerCamel for internals; exported wrapper + unexported testable twin taking an explicit transport.
Examples: `RegisterKey`/`registerKey`, `SignASN1`/`signASN1` (`tpm/tpm.go:131,147,223,239`), `HandleCommand`, `handleGetInfo`, `MakeCredentialDirect`, `startDeviceLocked`/`stopDeviceLocked` (suffix `Locked` = caller holds mutex, also `applyActiveLocked` in `tray/tray.go:77`).

**Variables:**
lowerCamel; short names in tight scope (`h`, `cs`, `d`, `up`, `req`, `ch`, `cid`); TPM handle is conventionally `thetpm`.

**Constants:**
- Protocol constants PascalCase with domain prefix in `ctap2`: `CmdGetInfo`, `StatusNoCredentials`, `COSEAlgES256`, `FlagUserVerified` (`ctap2/commands.go`).
- Unexported lowerCamel in transport packages: `cmdInit`, `errChannelBusy`, `keepaliveInterval` (`fidohid/fidohid.go:41-88`), `sigVerifyStatus` (`fprintd/fprintd.go:30`).
- Errors: `Err...` exported sentinels (`ctap2.ErrNoCredentials`, `fprintd.ErrNoDevice`), unexported `errClosed`, `errSignalStreamClosed`.

## Code Organization

**Import/Dependency Declaration:**
`goimports` style: stdlib block, blank line, third-party + module-internal block (internal imports mixed with third-party, sorted alphabetically).
```go
import (
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/moritzheiber/tpm-fido2-thinkpad-linux/attestation"
)
```

**File Structure:**
Package doc comment (newer packages: `fidohid`, `fprintd`, `internal/uhid`, `desktopnotify`, `tray`, `usbmon`), then consts/vars, types, constructor `New(...)`, public methods, private helpers at the bottom. `ctap2` splits one file per CTAP command plus `types.go`, `commands.go` (constants), `storage.go`.

Formatting: `gofmt -l` flags 8 files: `ctap2/{authenticatordata,commands,ctap2,getassertion,makecredential,types}.go`, `webauthn/{errors,types}.go` (misaligned struct/const blocks). All other packages are gofmt-clean; CI does not enforce gofmt.

## Type Safety/Documentation

**Approach:** Static Go types; CTAP2 CBOR maps modeled with struct tags `cbor:"N,keyasint,omitempty"` (`ctap2/types.go`); extension inputs kept as `map[string]interface{}` and re-marshalled into typed structs on demand (`ctap2/hmacsecret.go:25-33`). JSON envelopes for Native Messaging use `json.RawMessage` for deferred decoding (`nativemsg/types.go`, `webauthn/types.go`). Fixed-size crypto values use arrays (`[32]byte` rpIdHash, `[16]byte` AAGUID).

## Error Handling

**Pattern:** Two styles coexist.
- Library packages return wrapped errors with `fmt.Errorf("context: %w", err)` and join cleanup errors with `errors.Join` (`fprintd/fprintd.go:100,182`, `fidohid/fidohid.go:180`, `internal/uhid/uhid.go:88`).
- CTAP2 handlers log and map to a CTAP status byte, returning `(status, nil)`; detail is only in logs:
```go
credentialID, x, y, err := h.signer.RegisterKey(rpIDHash[:])
if err != nil {
	log.Printf("CTAP2 MakeCredential: RegisterKey error: %s", err)
	return StatusOther, nil
}
```
- `webauthn` maps errors to DOMException names via `MapErrorToResponse` (`webauthn/errors.go`); one branch compares error strings (`webauthn/handler.go:169,340`).
- `panic` only for impossible states: `mustRand` (`tpm/tpm.go:321`), HKDF read (`tpm/tpm.go:60`), attestation PEM parse (`attestation/attestation.go:46`).
- `main` uses `log.Fatalf` for startup failures.

Logging: stdlib `log` to stderr with `Lshortfile` (`tpmfido.go:39-40`), prefix convention `"<Layer> <Command>: ..."` (e.g. `"CTAP2 GetAssertion: ..."`, `"fidohid: ..."`, `"userpresence: ..."`). Logs include RP IDs and user names.

## Comments/Documentation

**Style:** Doc comments on most exported identifiers, explaining *why* in newer code (e.g. `fprintd/fprintd.go:1-8`, `internal/uhid/uhid.go:120,132`). Security-fix markers reference an earlier audit ID: `// H1:`, `// H2:`, `// H4:` (`webauthn/handler.go:49,74`, `ctap2/hmacsecret.go:54`). Byte-layout comments next to wire encodings (`fidohid/fidohid.go:21-37,378`).

## Concurrency Conventions

- `sync.Mutex` fields named `mu`; specialized `writeMu`, `readMu`, `lifecycleMu`.
- Goroutines launched via `sync.WaitGroup.Go` (Go 1.25) in `fidohid`.
- Result delivery via buffered `chan Result` of size 1.
- Cancellation via `context.Context`; 30 s is the ubiquitous timeout constant (UP, CTAPHID channel, CBOR op).

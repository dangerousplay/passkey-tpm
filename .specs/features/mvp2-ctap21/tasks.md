# MVP-2 CTAP 2.1 — Tasks and results

**Status:** Done. Real-fprintd E2E pending.

| Task | Status | Notes |
|---|---|---|
| P: PIN/UV auth protocols 1 & 2 | ✅ | `core::pin_protocol`; 22 tests; HKDF vs RFC 5869, AES vs NIST SP 800-38A; strict COSE key parser (exactly 5 labels, alg -25) — python-fido2 interoperates |
| R: `resident.v1` codec | ✅ | `wire::resident`; 15 tests + proptests + fuzz target; whole-decode Kani harness dropped (CBMC OOM/minutes), field-reader harness kept in the slow tier |
| Token + mismatch counter (Verus) | ✅ | `core::token`: permission/rpId/expiry/UP-consume/allows_unbound/BootMismatches; 103 verified total |
| Evidence method + ED flag (Verus) | ✅ | `UvMethod::{Fingerprint, PinUvAuthToken}`, 4 flag values proven |
| ctap2 rewrite | ✅ | `authn`, `client_pin`, `make_credential`, `get_assertion`, `cred_mgmt`, `info`, `state`, `common`; 19 scenario tests + 2 never-panic proptests |
| TpmOps additions | ✅ | `verify_pin`, `pin_is_set`, `pin_retries`/`set_pin_retries` (file, fail-closed), `resident_entries`/`store_resident_entries`, `reset_user` |
| Broker clock | ✅ | monotonic `now_ms` from the TPM worker |
| Agent prompts | ✅ | clientPIN UV token, reset, selection get UPNEEDED + prompt |
| E2E | ✅ | `scripts/e2e-local.sh` on AMD fTPM: libfido2 CTAP 2.0 flows + python-fido2 CTAP 2.1 suite (28 checks: setPIN, PIN token + touch, rk + hmac-secret (both protocols, deterministic TPM HMAC), credProtect echo, UV token without second gesture, credMgmt metadata/enumerate/update/delete, changePIN, selection, reset). The wrong-PIN check is opt-in (`E2E_ALLOW_DA_FAILURE=1`) because it increments the TPM DA counter |

## Deviations / follow-ups

- RP-bound credMgmt tokens can't delete/update yet (needs an unbound cm token) — stricter than CTAP 2.1 §6.8.
- Deleting a discoverable credential removes its metadata, but its credential ID still works if an RP holds it (no per-credential revocation; a reset revokes everything). Track: revocation list keyed by credential-ID tag.
- `getNextAssertion` reuses the UV of the initial getAssertion (CTAP 2.1 §6.3), through the UV gate.
- Users without a fingerprint reader can set and use a PIN for UV, but can't provide UP (needs the M4 trusted prompt).

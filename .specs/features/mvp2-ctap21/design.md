# MVP-2 CTAP 2.1 — Design

**Spec:** `spec.md` · **Status:** Approved (2026-10-03)

## Module layout

| Module | Crate | Content |
|---|---|---|
| `pin_protocol` | core | PIN/UV auth protocols 1 and 2: `KeyAgreement` (P-256, zeroized), `SharedSecret`, `encrypt`/`decrypt`/`authenticate`/`verify`, COSE key (alg -25) encoding and decoding |
| `token` (verified) | core | `PinUvAuthToken { bytes, permissions, rp_id_hash: Option, user_verified, user_present, issued_ms }`; Verus-verified `allows(perm, rp)`; expiry |
| `pin_retries` (verified) | core | existing; plus a per-boot mismatch counter |
| `ctap2/` | core | `mod.rs` (dispatch, `Authenticator`), `info.rs`, `make_credential.rs`, `get_assertion.rs`, `client_pin.rs`, `cred_mgmt.rs`, `ext.rs` (hmac-secret, credProtect) |
| `resident` | wire | `resident.v1` codec: `Vec<ResidentEntry { rp_id, rp_name, user_id, user_name, user_display_name, credential_id, created }>`, Kani panic-freedom |
| `adapter` | tpm | `TpmOps` storage additions (below) |

## `TpmOps` additions (backend = TPM + per-user files)

`verify_pin`, `pin_is_set` (done); `pin_retries(uid) -> u8`, `set_pin_retries(uid, u8)`;
`resident_list(uid) -> Vec<ResidentEntry>`, `resident_store(uid, Vec<ResidentEntry>)`;
`reset_user(uid)` (removes gates and files; next use provisions afresh).

## Per-user authenticator state (in `Authenticator`, memory only)

`HashMap<Uid, UserState { key_agreement: KeyAgreement, token: Option<PinUvAuthToken>,
mismatches: u8, next_assertion: Option<NextAssertion>, uv_failures: u8 }>`; time is passed in
(`now_ms`) so the core stays pure.

## Evidence

`UvEvidence` gains a kind: `Fingerprint` (from fprintd) or `PinToken` (from a valid
pinUvAuthParam on a token with `user_verified`). Both select the UV gate; flags come from the
evidence plus UP (gesture or token `user_present`).

## Flows

- **UV through a token:** clientPIN 0x06 → `NeedUv` → fingerprint → token (`uv` and `up`) → makeCredential with pinUvAuthParam → no second gesture (UP consumed from the token).
- **PIN:** clientPIN 0x09 → TPM `verify_pin` (retries decremented first) → token (`uv`, not `up`) → makeCredential → fingerprint gesture for UP → UV gate.
- **hmac-secret:** the platform key agreement is with the user's `KeyAgreement`; salts are decrypted in the core; the HMAC runs in the TPM through the UV or UP gate per the UV flag; the output is encrypted in the core.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| credProtect | always apply level 3, echo it | every gesture is a fingerprint anyway; strongest TPM policy |
| UP without a fingerprint reader | not supported in MVP-2 | needs a trusted prompt (M4) |
| uvRetries | in-memory counter, 5 consecutive no-match → `UV_BLOCKED`, PIN fallback | fprintd has no retry counter |
| Crypto crates | p256 0.13 (ecdh), aes 0.8, cbc 0.1, hkdf 0.12, hmac 0.12 | same RustCrypto generation as the workspace |

# MVP-1 Authenticator — Specification

**Milestone:** M1 (MVP-1)
**Scope:** Complex
**Status:** Approved (user: "continue with the next MVP", 2026-10-03)
**Depends on:** tpm-policy-model (done)

## Goal

A user can register and sign in on webauthn.io (Chromium, Firefox), and with `fido2-token`/`fido2-cred`, using their fingerprint. Credentials are enforced by the TPM policy model. Works on any Linux machine with a TPM 2.0 and fprintd.

## Cut line (MVP-1)

- **In:**
  - CTAP 2.0 over CTAPHID (uhid): `authenticatorGetInfo`, `authenticatorMakeCredential` and `authenticatorGetAssertion` with non-discoverable credentials.
  - CTAPHID INIT, PING, CBOR, CANCEL, KEEPALIVE, ERROR.
  - UV through fprintd: every operation needs a fingerprint match, so UP and UV are both set.
  - Packed self-attestation.
  - Broker (system service) plus agent (user service) over the system D-Bus.
- **Out (MVP-2):** clientPIN, CTAP 2.1 (`FIDO_2_1`), hmac-secret on the wire, discoverable credentials, credential management, reset, a presence-only gate, CTAP1/U2F, credentialsd.

## Requirements

| ID | Requirement |
|---|---|
| MVP1-01 | GetInfo reports `versions=["FIDO_2_0"]`, AAGUID, `options {rk:false, up:true, uv:<fprintd has enrolled fingerprints>, plat:false}`, `maxMsgSize ≥ 2048`, `maxCredentialCountInList = 8`, `maxCredentialIdLength = 1023`, `algorithms [ES256]`. |
| MVP1-02 | makeCredential: validates `clientDataHash` (32 B), `rp.id`, `user.id` (1..=64 B) and `pubKeyCredParams` (must include ES256 / -7, else `CTAP2_ERR_UNSUPPORTED_ALGORITHM`); rejects `rk=true` (`CTAP2_ERR_UNSUPPORTED_OPTION`); honours `excludeList` (`CTAP2_ERR_CREDENTIAL_EXCLUDED` after a fingerprint match). |
| MVP1-03 | Credential IDs carry a 16-byte tag, `HMAC-SHA-256(K_uid, rpIdHash ‖ body)[..16]`, where K_uid is a per-user key held by the broker. This lets the broker recognise its own credentials for this user and RP before any gesture. The TPM policy remains the enforcement; the tag is only an index. |
| MVP1-04 | getAssertion: `allowList` is required in MVP-1 (else `CTAP2_ERR_NO_CREDENTIALS`) and is processed up to 8 entries; the first entry whose tag verifies is used. No match: one fingerprint gesture, then `CTAP2_ERR_NO_CREDENTIALS` (no silent probing). |
| MVP1-05 | authData = rpIdHash ‖ flags ‖ signCount(0) ‖ [attestedCredentialData]. Flags: UP=1, UV=1 only when a fingerprint match for the calling user happened in this request (verified), AT on makeCredential only. |
| MVP1-06 | Signature = TPM ECDSA over SHA-256(authData ‖ clientDataHash) through the UV gate. Attestation: `fmt "packed"`, `alg -7`, `sig` by the credential key, no `x5c`. |
| MVP1-07 | CBOR: requests are decoded with depth ≤ 4, at most 32 map entries per map and maxMsgSize total; responses are canonical CTAP2 CBOR. The decoder is Kani-proven panic-free and fuzzed. |
| MVP1-08 | CTAPHID: 64-byte reports; channel allocation via INIT on the broadcast CID; reassembly enforces SEQ order 0..=127 and the declared length ≤ maxMsgSize; one transaction at a time (others get `ERR_CHANNEL_BUSY`); a 750 ms continuation timeout gives `ERR_MSG_TIMEOUT`; KEEPALIVE every 100 ms while the broker works; CANCEL aborts UV. The state machine invariants are verified with Verus. |
| MVP1-09 | Broker `passkey-tpm-uvd`: system D-Bus name `io.github.dangerousplay.PasskeyTpm1` (prefix pending confirmation), methods `Ctap(request: ay) -> ay` and `Cancel()`. The caller uid comes from the bus (`GetConnectionUnixUser`), never from the payload. Per-uid state lives in `$STATE_DIRECTORY/<uid>/`, with gates provisioned on first use. Calls are serialised per TPM. |
| MVP1-10 | UV via fprintd from the broker: `GetDefaultDevice`, `Claim(username)`, `VerifyStart("any")`, wait for `VerifyStatus` with done=true, `VerifyStop`, `Release`. Only signals from the owner of `net.reactivated.Fprint` are accepted. Timeout 30 s. A polkit rule grants verify + setusername to the `passkey-tpm` user only. |
| MVP1-11 | Agent `passkey-tpm-agent`: creates a uhid FIDO device (usage page 0xF1D0, VID:PID 1209:F1D0 placeholder until a pid.codes ID), relays CBOR to the broker, and shows a desktop notification naming the RP ("Touch the fingerprint reader to sign in to example.com"). |
| MVP1-12 | Packaging files (not installed by tests): systemd system unit (hardened), user unit, D-Bus system policy, polkit rule, udev rule (`uaccess` on `/dev/uhid` for the active seat), sysusers.d, tmpfiles.d. |
| MVP1-13 | No panic is reachable from agent or broker input (clippy panic lints, Kani on parsers, fuzzing on CBOR and CTAPHID). |

## Acceptance

- Integration: broker + swtpm + mock fprintd on a private D-Bus → makeCredential → getAssertion. Signature verified with `p256`, attestation verified, flags checked; wrong uid gets `NO_CREDENTIALS`; a cancelled UV gets `CTAP2_ERR_KEEPALIVE_CANCEL`.
- CTAPHID: unit tests plus Verus proofs plus a fuzz target.
- End-to-end (manual or privileged CI): `fido2-token -L` lists the device; `fido2-cred -M` / `fido2-assert -G` succeed against the uhid device.

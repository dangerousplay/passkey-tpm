# MVP-2 CTAP 2.1 — Specification

**Milestone:** M1 + M2 (MVP-2)
**Scope:** Complex
**Status:** Approved (user: "proceed with the next MVP", 2026-10-03)
**Depends on:** mvp1-authenticator (done), AD-013

## Goal

Discoverable passkeys, a PIN, PRF/hmac-secret and credential management, so that
`systemd-cryptenroll --fido2-device`, `pam_u2f`, browser passkey managers and libfido2's
`fido2-token` all work.

## Requirements

| ID | Requirement |
|---|---|
| M2-01 | getInfo: `versions ["FIDO_2_0","FIDO_2_1"]`; `extensions ["credProtect","hmac-secret"]`; options `rk:true, up:true, uv:<enrolled>, plat:false, clientPin:<pin set>, pinUvAuthToken:true, credMgmt:true, makeCredUvNotRqd:false`; `pinUvAuthProtocols [2,1]`; `transports ["usb"]`; `minPINLength 4`; `firmwareVersion`; `remainingDiscoverableCredentials`. |
| M2-02 | PIN/UV auth protocols 1 and 2 (CTAP 2.1 §6.5.6–7): P-256 ECDH key agreement (one key per user and broker start, regenerated on PIN mismatch), protocol-specific KDF, encrypt/decrypt and authenticate/verify. Secrets zeroized. |
| M2-03 | clientPIN subcommands getPINRetries, getKeyAgreement, setPIN, changePIN, getPinToken, getPinUvAuthTokenUsingUvWithPermissions, getUVRetries and getPinUvAuthTokenUsingPinWithPermissions, with the CTAP 2.1 parameter checks and error codes. |
| M2-04 | PIN rules: 4..=63 bytes and ≥ 4 code points; the stored PIN is `LEFT(SHA-256(pin),16)` checked by the TPM (AD-013); `pinRetries` (max 8) is persisted and decremented **before** each check; 3 mismatches per broker start give `PIN_AUTH_BLOCKED`; 0 retries give `PIN_BLOCKED` and disable built-in UV too (AD-010). The retry logic is verified with Verus. |
| M2-05 | pinUvAuthToken per user: 32 random bytes per broker start; permissions (mc 0x01, ga 0x02, cm 0x04); optional rpId binding; `userVerified`/`userPresent` flags; the token is invalidated after 10 minutes, on PIN change, on reset and on new token issue. The permission and rpId check is verified with Verus. |
| M2-06 | makeCredential/getAssertion accept `pinUvAuthParam` + `pinUvAuthProtocol`: verify `authenticate(token, clientDataHash)`, the permission and the rpId; UV flag from `token.userVerified`; UP from `token.userPresent` (consumed) or a fingerprint gesture. Zero-length `pinUvAuthParam` means touch, then `PIN_NOT_SET` or `PIN_INVALID`. A request with `uv` true while a PIN is set and no fingerprint is enrolled gives `PIN_REQUIRED`. |
| M2-07 | hmac-secret: makeCredential `{"hmac-secret": true}` creates the TPM HMAC keys and answers `hmac-secret: true` in the extensions (ED flag). getAssertion `{1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: protocol}`: verify saltAuth, decrypt one or two salts, TPM HMAC with CredRandomWithUV iff the UV flag, encrypt the output. |
| M2-08 | credProtect: requested levels are honoured by applying level 3 (every credential requires UV, AD-012) and echoing the applied level; never unsolicited. |
| M2-09 | Discoverable credentials: `rk:true` stores `{rpId, rp.name, user.id, user.name, user.displayName, credential ID, created}` in the broker's per-user `resident.v1` (atomic writes, 0600); an existing rp+user.id is replaced; at most 64 per user. getAssertion without allowList finds them (most recent first). The `user` member includes name/displayName only with UV. |
| M2-10 | getNextAssertion (0x08): continues a multi-credential getAssertion for the same user within 30 s without another gesture; the state is cleared by any other command. |
| M2-11 | credentialManagement (0x0A): getCredsMetadata, enumerateRPsBegin/GetNextRP, enumerateCredentialsBegin/GetNextCredential, deleteCredential, updateUserInformation; requires a token with the cm permission (`authenticate(token, subCommand ‖ subCommandParams)`). |
| M2-12 | authenticatorReset (0x07): after a fingerprint gesture, wipes only the caller's state (gates, PIN, discoverable credentials, MAC key): every credential ID of that user stops working. |
| M2-13 | authenticatorSelection (0x0B): fingerprint gesture, then OK. |
| M2-14 | Compatibility proven by `scripts/e2e-local.sh` on the real TPM: `fido2-token -S` (setPIN), `-C` (changePIN), `-I` (info), `fido2-cred -M -r -h` (resident + hmac-secret), `fido2-assert -G -h` (two calls with the same salt give the same output), `fido2-token -L -r`/`-D -i` (credMgmt), `fido2-token -R` (reset). |

## Out of scope (later)

largeBlob, minPinLength extension, authenticatorConfig (alwaysUv, setMinPINLength),
enterprise attestation, a presence-only gate for users without a fingerprint reader
(needs a trusted prompt, M4), CTAP1/U2F.

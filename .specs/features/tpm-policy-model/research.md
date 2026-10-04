# Research: TPM Policy Model for UV Binding

**Date:** 2026-10-03
**Method:** tss-esapi 7.7.0 and 8.0.0-alpha.3 crate sources (signatures checked), MS TPM 2.0 reference implementation, systemd and fprintd sources, Microsoft docs. TCG PDFs returned 403, so command semantics come from the reference implementation. UNVERIFIED items must be benchmarked or re-checked.

## Threat actors

- T1: another local user with `/dev/tpmrm0` access
- T2: malware running as the same user
- T3: offline attacker with the disk and credential IDs, on the same TPM
- T4: RP or network attacker holding credential IDs
- T5: PIN brute force

## Threat matrix (✓ stopped, ◐ partial, ✗ not stopped)

| Model | T1 | T2 | T3 | T4 | T5 |
|---|---|---|---|---|---|
| Go today (empty auth, no policy) | ✗ | ✗ | ✗ | ◐ | n/a |
| M1 authValue = KDF(PIN) on each key | ✓ (DA-limited) | ◐ | ✓ | ✓ | ◐ (only if lockoutAuth is set) |
| M2 PolicySecret, gate held by the user daemon | ✓ | ✗ (same uid) | ◐ (FDE) | ✓ | n/a |
| M3a PolicySigned by uvd, users keep TPM access | ✓ | ✓ (finger needed) | ◐ | ✓ | n/a |
| M3b broker-only DAC, authValue known to the broker | ✓ only via DAC | ✓ | ◐ | ✓ | software only |
| **M4 broker + PolicyOR of PolicySecret gates** | ✓ TPM-enforced | ✓ (UV/UP), ◐ (PIN) | ✓ PIN path / ◐ UV path | ✓ rpIdHash in policyRef | ✓ CTAP retries + TPM DA |

Residual risks no model fixes: faulTPM (AMD fTPM voltage glitch, https://arxiv.org/abs/2304.14717) and TPM-Fail (ECDSA timing leak on Intel PTT and some dTPMs, https://tpm.fail/tpmfail.pdf).

## Key findings per model

- **M1:** `ObjectChangeAuth` returns a new private blob, so credential IDs already held by RPs keep the old PIN. Put the PIN on a single gate object instead. `PolicySecret` binds the gate's Name, and authValue is not part of the Name. An NV-index gate plus `NV_ChangeAuth` leaves no stale blob, but `nv_change_auth` exists only in tss-esapi 8.0.0-alpha.3.
  - Prior art, systemd `--tpm2-with-pin`: PBKDF2-SHA256 with 10k iterations (Argon2id on newer main), PolicyAuthValue, salted session on SRK 0x81000001, AES-128-CFB.
  - Prior art, Windows: DA set to 32 tries with one forgiven every 10 min; a wrong lockout-auth attempt blocks for 24 h.
  - CTAP sends only `LEFT(SHA-256(PIN),16)`, so the KDF input is pinHash (exact spec section UNVERIFIED).
- **M2:** The kernel RM keeps sessions per fd (`drivers/char/tpm/tpm2-space.c`), so a policy session can't be handed to another process.
- **M3a:** aHash = H(nonceTPM‖expiration‖cpHashA‖policyRef). cpHashA pins the exact command. Rotation works through PolicyAuthorize.
  - Cost: an in-TPM ECDSA verify for each assertion.
  - Needs `tr_sess_get_nonce_tpm`, which exists only in 8.0-alpha.
  - Worthwhile only if unprivileged processes keep TPM access.
- **M3b vs M3a:** With a sole broker, PolicySigned adds nothing over PolicySecret, which costs an HMAC instead of an asymmetric verify. Pure DAC breaks as soon as another tss member exists (ssh-tpm-agent, tpm2-pkcs11), so keep TPM-enforced gates.
- **fprintd from a system service:**
  - `setusername` defaults to auth_admin_keep; `verify` defaults to allow_active only.
  - Claim and Verify on behalf of another user require setusername.
  - So ship a polkit rule granting verify + setusername to the broker uid; implicit root authorization is UNVERIFIED.
  - Check that the `VerifyStatus` sender is the owner of `net.reactivated.Fprint`.
  - Only one claim at a time, which conflicts with GDM/PAM.

## hmac-secret

- A KEYEDHASH key (sign, unrestricted, scheme HMAC-SHA256, sensitiveDataOrigin, no inSensitive data) gets a 32-byte key from the TPM DRBG (`CryptGenerateKeyedHash`). `TPM2_HMAC(key, salt)` then equals HMAC-SHA256(CredRandom, salt).
- CTAP 2.1 needs CredRandomWithUV and CredRandomWithoutUV, so each credential gets two keyedHash keys.

## Counter

- Use a constant 0. WebAuthn treats 0 as "counter not supported", and Apple synced passkeys always return 0. With fixedTPM keys, a counter adds little clone detection, and avoiding it avoids NV wear.

## Performance (UNVERIFIED, benchmark in M1)

- ECDSA P-256 sign takes about 130 ms on Intel PTT and about 69 ms on a dTPM.
- An estimated 200–400 ms per assertion over 8–10 commands.
- The persistent SRK removes about 230 ms of CreatePrimary keygen per operation (what the Go code pays today).
- No AMD fTPM data.

## tss-esapi APIs (verified)

**Methods on `Context`, identical in 7.7.0 and 8.0.0-alpha.3:**
- Policy: `policy_secret`, `policy_signed`, `policy_auth_value`, `policy_or`, `policy_command_code`, `policy_cp_hash`, `policy_get_digest`, `policy_authorize`
- Sessions: `start_auth_session`, `tr_sess_set_attributes`, `execute_with_session(s)`
- Objects: `create`, `load`, `sign`, `hmac`, `tr_set_auth`, `tr_from_tpm_public`, `flush_context`, `evict_control`, `load_external_public`, `verify_signature`, `object_change_auth`
- In 8.0.0-alpha.3, `sign` takes `impl Into<Option<HashcheckTicket>>` as its last parameter.

**Helpers:** `SymmetricDefinition::AES_128_CFB`, `KeyedHashScheme::HMAC_SHA_256`, `ObjectAttributesBuilder::with_no_da` / `with_user_with_auth` / `with_admin_with_policy`, `AuthHandle: From<ObjectHandle | NvIndexHandle>`.

**8.0.0-alpha.3 only:** `tr_sess_get_nonce_tpm`, `nv_change_auth`.

**Missing in both:** DictionaryAttackLockReset and DictionaryAttackParameters, PolicyNV, PolicyTicket, PolicyCounterTimer, CreateLoaded. Use `tss-esapi-sys` FFI or `tpm2_dictionarylockout`.

## Sources

- https://docs.rs/tss-esapi/7.7.0/tss_esapi/struct.Context.html
- https://docs.rs/crate/tss-esapi/8.0.0-alpha.3
- https://github.com/microsoft/ms-tpm-20-ref (`EA/PolicySigned.c`, `Symmetric/HMAC.c`, `crypt/CryptUtil.c`)
- https://github.com/systemd/systemd/blob/main/src/shared/tpm2-util.c
- https://gitlab.freedesktop.org/libfprint/fprintd (`data/net.reactivated.fprint.device.policy.in`, `src/device.c`)
- https://github.com/torvalds/linux/blob/master/drivers/char/tpm/tpm2-space.c
- https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals
- https://www.w3.org/TR/webauthn-3/
- https://developer.apple.com/forums/thread/712079
- https://tpm.fail/tpmfail.pdf
- https://arxiv.org/abs/2304.14717
- https://github.com/tpm2-software/tpm2-tools (tpm2_policysigned, tpm2_dictionarylockout man pages)
- Pulse Security, TPM bus sniffing: UNVERIFIED (not fetched)

---

## T0: CTAP / WebAuthn spec verification (2026-10-03)

**Sources:**
- CTAP 2.1 PS (2021-06-15)
- CTAP 2.2 PS (2025-07-14): hmac-secret moves to §12.7, hmac-secret-mc is §12.8
- WebAuthn L3 (W3C Rec 2026-08-25)

| Item | Finding | Section | Design impact |
|---|---|---|---|
| Stored PIN | The authenticator stores `LEFT(SHA-256(newPin),16)`. After setPIN/changePIN it only ever receives pinHash. | 2.1 §6.5.5.5–6 | Argon2id(pinHash16, salt) is the right authValue input. Record the PIN's code-point length at setPIN for minPINLength. |
| PIN delivery | paddedNewPin must decrypt to exactly 64 B. newPinEnc is 64 B (protocol 1) or 80 B (protocol 2). PIN is 4 code points minimum, 63 bytes maximum. | §6.5.1, §6.5.5.5 | Enforce in the core. |
| Retries | ≤ 8 retries. At 0, **both clientPIN and built-in UV are disabled** until reset. The counter is decremented **before** verification. 3 consecutive mismatches give PIN_AUTH_BLOCKED until a power cycle. | §6.5.2.2, §6.5.5.7.2 | Persist the decremented counter before the Argon2 + TPM attempt. A 0 count also blocks the fingerprint path. The per-boot counter is volatile; whether a daemon restart counts as a "power cycle" is UNVERIFIED, so require a reboot or a presence action. TPM DA threshold must be > 8. |
| hmac-secret | Two 32-byte CredRandoms; output = HMAC-SHA-256(CredRandom, salt). Selection uses the **response UV bit**. Mandatory for FIDO_2_1. Salts are 32 or 64 B. Protocol 2 uses a random IV. | 2.1 §12.5, §9, §6.5.6–7 | Two TPM HMAC keys match the spec. For credProtect=3 the WithoutUV key is unreachable (the spec only says SHOULD generate it). |
| signCount | Authenticators without a counter "leave the signCount … constant at zero"; RPs compare only when non-zero. | WebAuthn L3 §6.1.1, §7.2 | Conformant (deviates from a SHOULD; recorded in ADR 0003). |
| Credential ID | ≤ 1023 B. The default CTAP message cap is 1024 B unless maxMsgSize says otherwise. | WebAuthn §5.1, §6.5.1; CTAP §6.4, §8 | Advertise `maxMsgSize` ≥ 2048 and `maxCredentialIdLength`. Keep IDs ≲ 700 B. |
| credProtect | Level 3: UV is always required. Level 2 without UV: only with an allowList. Level 1: always usable. MUST be supported when UV exists. Don't send unsolicited output. | §12.1, §6.2.2 | Omitting the UP branch for level 3 is correct. |
| Attestation | No text allows a CTAP authenticator to emit `none` on its own (UNVERIFIED). Packed self-attestation (zero AAGUID, no x5c) passes clients untouched. | WebAuthn §5.1.3, §7.1 | **Use packed self-attestation**, not `none` (supersedes the M2 roadmap note). |
| uv option | `uv` true = built-in UV configured. 2.2 requires explicit clientPin/uv values when rk = true. | §6.4 | Report `uv` from the fprintd enrollment state. Implement getPinUvAuthTokenUsingUvWithPermissions. |
| alwaysUv | Optional; needs authenticatorConfig. | §7.2.3 | Defer to M2. |

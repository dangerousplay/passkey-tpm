# TPM Policy Model — Specification

**Feature:** TPM key protection and UV binding for passkey-tpm (ADR-003)
**Milestone:** M1
**Scope:** Complex (security-critical, new domain)
**Status:** Approved (2026-10-03)

## Problem

The Go implementation enforces user verification only in software. TPM keys have empty auth and no policy, and the hmac-secret seed sits in plaintext inside the credential ID (CONCERNS.md #1, #2; STATE L-001, L-002). passkey-tpm needs the TPM itself to refuse signing or HMAC unless the authorization the authenticator demands has been satisfied.

## Threat model

- T1: another local user with `/dev/tpmrm0` access
- T2: malware running as the same user
- T3: offline attacker with the disk and credential IDs, on the same TPM
- T4: RP or network attacker holding credential IDs
- T5: PIN brute force

**Out of scope:** physical TPM attacks (faulTPM, active bus interposer beyond SRK Name pinning), kernel/root compromise, TPM-Fail timing leaks (mitigated by choosing the TPM vendor and firmware, not by us).

## Requirements

| ID | Requirement |
|---|---|
| TPM-01 | No credential private key or hmac-secret CredRandom ever exists outside the TPM in plaintext. Credential IDs contain only TPM-wrapped blobs and public data. |
| TPM-02 | A credential key can sign only inside a policy session that satisfied one of the gates (PIN, UV or UP) of the **owning user**, using a policyRef bound to the credential's rpIdHash. `userWithAuth` is clear. |
| TPM-03 | A process holding `/dev/tpmrm0` access but not the gate secrets can't sign with or HMAC using any credential (T1), even with valid credential IDs. |
| TPM-04 | Only the privileged broker `passkey-tpm-uvd` (dedicated system user) holds gate secrets. Same-user processes reach credentials only through the broker. The UV and UP gates are satisfied only after a fresh fprintd match or a presence gesture for that user (T2). |
| TPM-05 | Gates are per user. The broker resolves the gate from the caller's uid (`SO_PEERCRED`/D-Bus credentials), never from request data. User B can't exercise user A's credential even with A's credential ID. |
| TPM-06 | A credential ID presented for RP X can't be used to produce an assertion for RP Y: the TPM enforces this through policyRef = SHA-256(tag ‖ rpIdHash) (T4). |
| TPM-07 | hmac-secret uses two TPM keyedHash keys per credential: CredRandomWithUV gated by PIN/UV, and CredRandomWithoutUV gated by UP. Output = HMAC-SHA256(CredRandom, salt) computed by `TPM2_HMAC`. |
| TPM-08 | The PIN gate's authValue = Argon2id(pinHash16, per-user salt). The PIN gate has DA protection (`noDA` clear). The UV and UP gates are high-entropy and have `noDA` set. |
| TPM-09 | Changing the PIN does not invalidate existing credentials, and the old PIN stops working. |
| TPM-10 | All gate auth and HMAC outputs cross the TPM bus only inside salted sessions with parameter encryption (AES-128-CFB), bound to the persistent SRK whose Name is pinned at provisioning. |
| TPM-11 | Provisioning uses the TCG ECC P-256 SRK at 0x81000001: reused if present, created otherwise. A Name mismatch at runtime is reported as an authenticator reset, and no silent re-provisioning happens. |
| TPM-12 | credProtect level 3 (userVerificationRequired) omits the UP branch from the credential's policy. |
| TPM-13 | The signature counter is always 0. |
| TPM-14 | The DA policy is documented and configurable. passkey-tpm never sets or changes `lockoutAuth` without an explicit admin command, and warns when lockoutAuth is empty (T5 weakened). |
| TPM-15 | A TPM clear or SRK loss is detected and surfaced to the user (all credentials invalid), not crashed on. |
| TPM-16 | Credential ID ≤ 1023 bytes for non-discoverable credentials. Discoverable credentials may use a short random ID with the blobs stored locally (root-owned, per user). |
| TPM-17 | Assertion latency ≤ 500 ms (p95) on reference fTPM/dTPM, excluding the UV gesture. |

## Acceptance

- Each of TPM-02, -03, -05 and -06 has a negative test against swtpm or the in-process simulator, covering: a direct `/dev/tpmrm0` client with a valid credential ID, a cross-user broker request, an RP swap and a wrong PIN.
- TPM-09 test: change the PIN, the old PIN fails, the new PIN works, and old credentials still work.
- TPM-17 benchmark on at least one AMD fTPM, one Intel PTT and one dTPM, recorded in the docs.

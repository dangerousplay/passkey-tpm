# Threat Model

## Assets

- Credential private keys (ECDSA P-256), which never leave the TPM.
- hmac-secret CredRandom values (WithUV / WithoutUV), which never leave the TPM.
- Per-user gate secrets (UV/UP authValues) and PIN state, held by the broker.
- The user's PIN.

## Trust boundaries

```
browser / libfido2 ──hidraw/uhid──▶ passkey-tpm-agent (user, untrusted for security decisions)
                                        │ system D-Bus (caller uid from bus credentials)
                                        ▼
                                 passkey-tpm-uvd (system user `passkey-tpm`, verified core)
                                   │                         │
                                   ▼                         ▼
                           TPM 2.0 (/dev/tpmrm0)        fprintd (polkit-granted)
```

## Adversaries

| ID | Adversary | Goal | Main defence |
|---|---|---|---|
| T1 | Other local user (possibly in the `tss` group) | Use someone else's credential | TPM PolicySecret gates per user; keys have `userWithAuth` clear |
| T2 | Malware running as the same user | Sign without the user's consent | Gate secrets held only by the broker; signing requires a fresh fingerprint match, presence gesture, or PIN |
| T3 | Offline attacker with the disk and credential IDs | Use or extract credentials | Blobs are TPM-wrapped (`fixedTPM`); PIN path has TPM dictionary-attack protection; UV/UP gate files require full-disk encryption |
| T4 | Relying party or network attacker holding credential IDs | Cross-site use, PRF derivation | policyRef binds every credential to its rpIdHash inside the TPM; CredRandom is a TPM HMAC key |
| T5 | PIN guessing | Unlock the PIN path | The TPM compares the PIN against the DA-protected PIN gate; CTAP 8-retry counter (verified) |

## Out of scope

- Physical attacks on the TPM (faulTPM voltage glitching, active bus interposers beyond SRK Name pinning).
- TPM firmware side channels (TPM-Fail); choose patched TPM firmware.
- Kernel or root compromise.

## Known limitations

- **Prompt spoofing (T2).** The agent shows prompts in the user session, so same-user malware
  could get a gesture approved for a different relying party than the one shown. Tracked for
  M4 (broker-driven or credentialsd-ui prompt).
- **TPM DA lockout is machine-wide.** T1 can trigger it with its own objects, which blocks the PIN
  path for everyone; fingerprint and presence keep working (`noDA` gates).
- fprintd matching is not attested to the TPM; the broker is the UV enforcement point.
- The PIN is checked by the TPM (DA-protected) but is not a separate cryptographic branch of the key policy: the broker then uses the UV gate (ADR 0003 amendment 1). This makes no difference against T1–T5, because the UV gate secret is held only by the broker.
- On firmware TPMs (AMD fTPM, Intel PTT, Pluton), gate secrets are sent without session encryption: there is no external bus. Discrete TPMs use salted, encrypted sessions.

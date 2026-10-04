# ADR 0003: Privileged broker and per-user PolicyOR of PolicySecret gates

- Status: Accepted
- Date: 2026-10-03
- Details: `.specs/features/tpm-policy-model/design.md`

## Context

TPM policies can require that a secret was presented, but they cannot attest that a fingerprint
matched. The process holding gate secrets is therefore the UV enforcement point and must run
under a different uid from the user.

## Decision

- A privileged broker (`passkey-tpm-uvd`) is the only holder of gate secrets. An unprivileged
  per-user agent handles transport and UI.
- Each credential key has `userWithAuth` clear and the authPolicy
  `PolicyOR(P_pin, P_uv, P_up)`, where
  `P_x = PolicyCommandCode(cc) ; PolicySecret(gate_x[uid], policyRef = SHA-256(tag_x ‖ rpIdHash))`.
  credProtect level 3 omits `P_up`.
- Gates are per user and resolved from the D-Bus caller uid. The PIN gate is an NV index
  (DA-protected, authValue = Argon2id(pinHash16, salt), changed with `NV_ChangeAuth`). The UV
  and UP gates are keyedHash objects with `noDA` and 32-byte random authValues.
- hmac-secret uses two TPM keyedHash HMAC keys per credential (WithUV, WithoutUV).
- Persistent TCG SRK at 0x81000001 with its Name pinned; salted, parameter-encrypted sessions.
- The signature counter is always 0.

## Alternatives rejected

- authValue = KDF(PIN) per key: credentials already held by RPs keep the old PIN after a change,
  and there is no fingerprint path.
- Gate held by the user's own daemon: same uid as same-user malware.
- PolicySigned: no extra security once the broker is the sole gate holder, and costs an
  in-TPM signature verification per assertion.
- File permissions only: breaks as soon as any other process has TPM access.

## Consequences

- A system service, a dedicated system user and a polkit rule for fprintd are required. Users
  no longer need the `tss` or `plugdev` groups.
- tss-esapi 7.7 lacks `NV_ChangeAuth` and the DA commands, so a small audited FFI module is needed.
- DA lockout is machine-wide and shared with other TPM users (LUKS, Windows on dual-boot).

## Amendment 1 (2026-10-03): measured on an AMD fTPM

The model above took 2.5 s per assertion on real hardware, so it was revised (STATE AD-013):

- **Gates:** all gates are NV indexes. UV/UP are `noDA` with random 32-byte secrets; the PIN gate is DA-protected. Using a gate needs no `TPM2_Load`.
- **Key policy:** each branch is `PolicySecret(gate, SHA-256(tag ‖ rpIdHash))`, with no `PolicyCommandCode`. credProtect=3 keys have the single UV branch; level 1 keys have `PolicyOR(UV, UP)`.
- **PIN:** the broker verifies it against the PIN gate, where the TPM does the comparison and counts DA failures, then uses the UV gate. Compared with a PIN branch this loses nothing: whoever holds the UV gate secret (only the broker) can already sign.
- **Sessions:** salted, parameter-encrypted sessions are used only for discrete TPMs. Firmware TPMs have no external bus to protect.
- **SRK:** any TCG SRK template at 0x81000001 is reused (RSA-2048 is common).

Result: 577 ms p50 per assertion on the AMD fTPM (from 2521 ms), 221 ms per registration.

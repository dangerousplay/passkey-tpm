# PIN Without Fingerprint — Specification

**Size:** Large (core, broker D-Bus API, agent, tray)
**Status:** Implemented (2026-10-13); desktop UAT (real notification server, zenity) pending
**Decisions (user, 2026-10-13):** cover both the authenticator and the tray; presence for users without a fingerprint comes from an Allow/Deny desktop notification; keep presence pluggable so other passkey types/providers can be added later. Supersedes the "UP needs a fingerprint" part of AD-012 and the MVP-2 out-of-scope item "presence-only gate for users without a fingerprint reader" (AD-022).

## Problem Statement

A user without a fingerprint reader, or with none enrolled, can set a PIN but then can't register or sign in: presence (UP) only comes from a fingerprint match, so every makeCredential/getAssertion ends in `CTAP2_ERR_NOT_ALLOWED`. Laptops without a reader can't use passkey-tpm at all.

## Goals

- [ ] A user with no enrolled fingerprint can set a PIN (browser, `fido2-token -S` or the tray) and register/sign in with it, confirming presence with a notification click
- [ ] Presence is a broker-side step that any front-end can serve (agent today; credentialsd provider later)

## Out of Scope

| Feature | Reason |
|---|---|
| Spoof-proof presence | Notification is same-user UI (threat model); trusted prompt stays M4 |
| PIN-free operation | Credentials are credProtect=3; UV is always required |
| Presence prompt for users *with* fingerprints | They keep the fingerprint touch (stronger) |

---

## User Stories

### P1: PIN-only register and sign-in ⭐ MVP

1. WHEN a user has no enrolled fingerprint (no reader, fprintd unavailable, or zero fingers) AND a request carries a valid PIN-derived pinUvAuthParam (makeCredential/getAssertion) THEN the core SHALL ask for presence (`Step::NeedPresence`) instead of returning NOT_ALLOWED, and on confirmation SHALL sign with token UV evidence through the UV gate (PIN-01)
2. WHEN such a user's platform sends a zero-length pinUvAuthParam (touch to select), authenticatorSelection or authenticatorReset THEN the core SHALL ask for presence (PIN-02)
3. WHEN presence is denied THEN the response SHALL be OPERATION_DENIED; timeout → USER_ACTION_TIMEOUT; cancel → KEEPALIVE_CANCEL; no presence front-end → NOT_ALLOWED; none of these SHALL count as UV failures (PIN-03)
4. WHEN a presence-only pending request receives anything but `Present`/`Matched` THEN no signature SHALL be produced; `Present` on a fingerprint (`NeedUv`) request SHALL be OPERATION_DENIED (PIN-04)
5. WHEN a request has no pinUvAuthParam and the user has no fingerprint THEN behaviour is unchanged (PUAT_REQUIRED if a PIN is set — now also for getAssertion — else NOT_ALLOWED) (PIN-05)
6. WHEN the PIN is blocked THEN presence-only requests SHALL fail with PIN_BLOCKED before prompting (PIN-06)

### P1: Presence over D-Bus ⭐ MVP

1. WHEN the core asks for presence THEN the broker SHALL emit `PresenceRequested(t id, s prompt)` as a unicast signal to the connection that sent `Ctap`, and wait up to the verify timeout (PIN-07)
2. WHEN `ConfirmPresence(t id, b allow)` arrives from that same unique bus name THEN the broker SHALL complete with Present/Denied; from any other connection it SHALL be rejected with AccessDenied and change nothing (PIN-08)
3. WHEN `Cancel` is called or the verify timeout passes THEN the pending presence SHALL end (KEEPALIVE_CANCEL / USER_ACTION_TIMEOUT) (PIN-09)

### P1: Agent presence prompt ⭐ MVP

1. WHEN the agent receives `PresenceRequested` from the broker's current owner THEN it SHALL show a notification "Allow passkey-tpm for <rp>?" with Allow/Deny actions, replacing the fingerprint prompt, and call `ConfirmPresence` with the choice (closing = deny) (PIN-10)

### P2: Set or change the PIN from the tray

1. WHEN the broker is reachable THEN the tray SHALL show a "PIN: set / not set" line and "Set PIN…" (not set) or "Change PIN…" (set) (PIN-11)
2. WHEN chosen THEN the tray SHALL ask for the PIN with zenity (or kdialog), check length ≥ 4 characters and ≤ 63 bytes and confirmation, and run clientPIN setPIN/changePIN (protocol 2) through the broker's `Ctap` (PIN-12)
3. WHEN it finishes THEN a notification SHALL report success or the CTAP error in words (wrong PIN, blocked, policy) (PIN-13)
4. WHEN no fingerprint is enrolled but a PIN is set THEN the tray health SHALL be Ready ("PIN only") (PIN-14)

## Edge Cases

- Forged `PresenceRequested` (not from the broker owner) → agent ignores it
- Late click after timeout → `ConfirmPresence` unknown id → error, ignored by the agent
- No zenity/kdialog → notification explaining what to install

## Verification (2026-10-13)

| IDs | Evidence |
|---|---|
| PIN-01..06 | `crates/core/src/ctap2/tests.rs`: `without_fingerprint_pin_and_presence_register_and_sign` (UV gate for both signatures), `without_fingerprint_refused_presence_signs_nothing`, `presence_never_completes_a_fingerprint_request`, `without_fingerprint_uv_is_never_assumed`, `without_fingerprint_select_touch_and_reset_need_presence`, `without_fingerprint_blocked_pin_stops_before_prompting` |
| PIN-07..09 | `crates/uvd/tests/broker.rs` (swtpm + private bus): register after Allow, Deny → 0x27, Cancel → 0x2D; a second connection's `ConfirmPresence` gets AccessDenied |
| PIN-10 | Agent builds and passes clippy; notification actions not exercised automatically (needs a notification server) — UAT |
| PIN-11..14 | `crates/tray/tests/pin.rs` (real broker on swtpm): getInfo PIN state, setPIN, already set, changePIN wrong/right; tray unit tests for menu/health; zenity/kdialog dialog — UAT |

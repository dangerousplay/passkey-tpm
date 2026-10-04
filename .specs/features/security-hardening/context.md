# Security Hardening — Decisions on Gray Areas

## G1: Binding the authenticator to the seat user (decided 2026-10-04, AD-020)

**Decision:** both sides check, and both fail closed.

- **Broker (H5):** before serving `Ctap`, uvd asks logind whether the caller's uid has a session that is on a seat (`ListSessions`, non-empty seat) and `Active`. If not, it answers `CTAP2_ERR_OPERATION_DENIED` (0x27) and logs `denied uid=…`. Errors talking to logind count as "not active".
- **Agent (H6):** the agent watches logind (`SessionNew`/`SessionRemoved` on the Manager, `PropertiesChanged` on sessions, plus a 2 s poll). While its user isn't active on a seat it removes its HID device (`UHID_DESTROY`) and re-creates it on the same `/dev/uhid` handle when the user returns. On removal, the CTAPHID state is reset and an in-flight broker request is cancelled.

**Why both:** the broker check alone leaves a hole. Descriptors are only checked at open, so user B could open A's hidraw node while B is at the seat, keep the fd, and use it after A switches back, when the broker sees A as active again. Removing the device invalidates every descriptor (verified in the VM: `test_descriptor_opened_before_a_switch_stops_working`). The agent check alone isn't enough either, because the agent runs as the user and same-user code can skip it.

**Why by uid and not by caller PID:** the agent runs under `user@.service`, outside any login session, so `GetSessionByPID` doesn't resolve it.

**What we gave up:**
- A user with only a seatless session (SSH, `machinectl shell`) can't use the authenticator.
- A user logged in on two seats is served while either seat is active.
- Without logind, nothing works: Linux + systemd is the supported platform (AD-015).

**Residual risk:** for up to ~2 s after a switch (if the signal is missed) A's device still exists while B is active, so B could open it. That descriptor dies when the device is removed, and the broker refuses A's requests while A is in the background.

**Identification:** each agent's device carries `HID_PHYS=passkey-tpm-agent/uid=<uid>`, so tools and tests can tell users' devices apart.

## G2, G3, G4

Still open. They're needed for phase 2/3 (H10a, H16, H13). The recommendations in the spec stand.

## Notes from the P1 implementation

- **H1:** `StartServiceByName` runs only when `net.reactivated.Fprint` has no owner. dbus-daemon 1.16 answers `ServiceUnknown` for an owned name that has no `.service` file, which would break a hand-started fprintd.
  - If fprintd can't be reached, uvd logs it and advertises no built-in UV, so clients fall back to the PIN.
  - A three-state `UserInfo` in core (enrolled / not enrolled / unavailable) would be cleaner. Deferred.
- **H3:** the fingerprint gesture path checks `UV_BLOCKED`, then `PIN_BLOCKED`, before prompting.
  - When a PIN token already supplied UV and the fingerprint is only needed for presence, only `PIN_BLOCKED` applies. That keeps the PIN usable as a fallback once fingerprint UV is blocked.
  - Trade-off: a PIN holder gets unlimited presence attempts.
  - `uv_failures` stays in memory, so it resets when the broker restarts.
  - Reset and Selection (`need_gesture`) are unchanged: reset must stay reachable when the PIN is blocked.
- **`MAX_UV_RETRIES` is 5** (`common.rs`), not 3 as the task text said.

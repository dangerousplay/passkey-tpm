# Tray Icon — Specification

**Size:** Large (new crate, fprintd enrollment API, packaging)
**Status:** Implemented (2026-10-13); real-desktop UAT pending
**Decisions:** `context.md` (gray areas settled with the user, 2026-10-13)

## Problem Statement

passkey-tpm has no visible presence in the desktop. A user can't tell whether the fingerprint reader was found, whether the broker answers or whether the virtual key is up, without running `passkey-tpm info` or `systemctl`. Users with a reader but no enrolled finger also need GNOME Settings / `fprintd-enroll` before any passkey works.

## Goals

- [ ] A tray icon (StatusNotifierItem) with a fingerprint icon shows the reader, broker and virtual-key status at a glance
- [ ] When a reader is detected, the menu offers "Enroll new fingerprint", which enrolls the next free finger through fprintd with progress notifications

## Out of Scope

| Feature | Reason |
|---|---|
| Deleting fingerprints, choosing the finger | User chose "next free finger" (context.md D3); GNOME Settings / `fprintd-delete` cover deletion |
| Listing/deleting passkeys, PIN change | M4 management UI |
| Trusted (spoof-proof) prompts | The tray runs in the user's session like the agent; see threat model "prompt spoofing" |
| XEmbed / legacy tray hosts | SNI is the freedesktop standard; GNOME needs the AppIndicator extension (documented) |
| Enrolling for another user | fprintd polkit `setusername`; not a tray concern |

---

## User Stories

### P1: Status at a glance ⭐ MVP

**User Story**: As a passkey-tpm user, I want a fingerprint icon in my tray that tells me whether everything works, so that I know why a sign-in might fail.

**Acceptance Criteria**:

1. WHEN `passkey-tpm-tray` starts in a session with an SNI host THEN it SHALL register a StatusNotifierItem with the `fingerprint` themed icon and the title "passkey-tpm" (TRAY-01)
2. WHEN the status is refreshed THEN the menu SHALL show three read-only lines: fingerprint reader (device name and enrolled finger count, or "not detected"), broker ("reachable" / "unreachable"), virtual key ("active" / "inactive") (TRAY-02)
3. WHEN all three are healthy and at least one finger is enrolled THEN the item status SHALL be `Active` and the tooltip SHALL say "Ready"; otherwise it SHALL be `NeedsAttention` with a tooltip naming the first problem (TRAY-03)
4. WHEN the tray runs THEN it SHALL refresh the status at start, every 10 s, after an enrollment ends and on the "Refresh" menu item (TRAY-04)
5. WHEN any probe fails or hangs THEN that line SHALL show the failure and the probe SHALL give up after 5 s without blocking the menu (TRAY-05)

**Independent Test**: run `passkey-tpm-tray` on a KDE/GNOME+AppIndicator session; stop `passkey-tpm-agent.service` → virtual key line flips to inactive within 10 s or on Refresh.

### P1: Enroll a fingerprint from the tray ⭐ MVP

**User Story**: As a user with a reader but no (or few) enrolled fingers, I want to enroll a finger from the tray, so that I don't need another tool before using passkeys.

**Acceptance Criteria**:

1. WHEN a reader is detected THEN the menu SHALL show "Enroll new fingerprint"; WHEN no reader is detected THEN it SHALL NOT be shown (TRAY-06)
2. WHEN the user picks it THEN the tray SHALL choose the first finger not yet enrolled in the order right-index, left-index, right-middle, left-middle, right-thumb, left-thumb, right-ring, left-ring, right-little, left-little (TRAY-07)
3. WHEN all ten fingers are enrolled THEN the item SHALL be disabled with the label "All fingers enrolled" (TRAY-08)
4. WHEN enrolling THEN the tray SHALL `Claim("")` (the calling user) and `EnrollStart(finger)` on fprintd's default device, so fprintd's own polkit action `net.reactivated.fprint.device.enroll` authorises it (TRAY-09)
5. WHEN fprintd emits `EnrollStatus` THEN the tray SHALL show a notification per stage (stage passed / retry hint / completed / failed) naming the finger (TRAY-10)
6. WHEN enrollment ends for any reason (completed, failed, error, 120 s timeout including the polkit dialog, cancel, quit) THEN the tray SHALL send `EnrollStop` (if started) and `Release` (if claimed) (TRAY-11)
7. WHILE enrolling THEN the enroll item SHALL be replaced by "Cancel enrollment" and a second enrollment SHALL NOT start (TRAY-12)
8. WHEN `EnrollStatus` arrives from a sender other than the resolved fprintd owner or another object path THEN it SHALL be ignored (TRAY-13)

**Independent Test**: on the VM (libfprint virtual device) or real hardware, pick "Enroll new fingerprint", authenticate in the polkit dialog, touch N times → "Fingerprint enrolled" notification, enrolled count +1.

### P2: Ships with the packages

**User Story**: As a packager/user, I want the tray to start with my desktop session.

**Acceptance Criteria**:

1. WHEN installed from the packages THEN `/usr/bin/passkey-tpm-tray` and `/etc/xdg/autostart/passkey-tpm-tray.desktop` SHALL be present (TRAY-14)
2. WHEN the tray is built THEN `cargo xtask ci` (incl. cargo-deny with a ksni-scoped Unlicense exception) SHALL pass (TRAY-15)

---

## Edge Cases

- WHEN no SNI host (watcher) exists THEN the tray SHALL log it and keep retrying registration (ksni default) rather than exit
- WHEN fprintd is not installed THEN reader = "not detected (fprintd unavailable)", no enroll item
- WHEN the user cancels the polkit dialog THEN `Claim`/`EnrollStart` fails → "Enrollment not authorised" notification, device released
- WHEN another process holds the device (`AlreadyInUse`) THEN "Fingerprint reader busy" notification
- WHEN `enroll-duplicate` is reported (finger already enrolled under another name) THEN fail with "This finger is already enrolled"
- WHEN the agent unit doesn't exist (non-systemd user session) THEN virtual key = "unknown"

---

## Requirement Traceability

| ID | Story | Task | Status |
|---|---|---|---|
| TRAY-01 | P1 Status | T4 | Verified |
| TRAY-02 | P1 Status | T3, T4 | Verified |
| TRAY-03 | P1 Status | T3 | Verified |
| TRAY-04 | P1 Status | T4 | Verified |
| TRAY-05 | P1 Status | T3 | Verified |
| TRAY-06 | P1 Enroll | T4 | Verified |
| TRAY-07 | P1 Enroll | T3 | Verified |
| TRAY-08 | P1 Enroll | T3, T4 | Verified |
| TRAY-09 | P1 Enroll | T1 | Verified |
| TRAY-10 | P1 Enroll | T1, T4 | Verified |
| TRAY-11 | P1 Enroll | T1 | Verified |
| TRAY-12 | P1 Enroll | T4 | Verified |
| TRAY-13 | P1 Enroll | T1 | Verified |
| TRAY-14 | P2 Packaging | T5 | Verified |
| TRAY-15 | P2 Packaging | T2, T5 | Verified |

**Coverage:** 15 total, 15 mapped to tasks, 15 verified (unit + mock-fprintd integration + E2E on a private bus; real SNI host/polkit UAT pending).

## Success Criteria

- [ ] From a fresh install with no enrolled finger, a user enrolls one from the tray and registers on webauthn.io without opening a terminal

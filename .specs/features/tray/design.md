# Tray Icon — Design

## Architecture

```
passkey-tpm-tray (user session, XDG autostart)
 ├─ ksni Tray  ── session bus ──> org.kde.StatusNotifierWatcher (KDE, GNOME+AppIndicator, waybar, …)
 │    menu callbacks ──mpsc──> command loop
 ├─ command loop (tokio)
 │    Refresh ─> probes (each bounded by 5 s) ─> Handle::update(snapshot)
 │    Enroll  ─> passkey_tpm_uv::fprintd::enroll(...) ─> notifications per EnrollStatus
 │    Cancel  ─> CancellationToken
 └─ probes
      reader : system bus → fprintd GetDefaultDevice, name/scan-type, ListEnrolledFingers("")
      broker : system bus → Introspect io.github.dangerousplay.PasskeyTpm1 (allowed by the bus policy; D-Bus activates the broker)
      key    : session bus → systemd1 LoadUnit("passkey-tpm-agent.service") → LoadState / ActiveState
```

## Components

### `passkey-tpm-uv::fprintd` (extended)

- `enrolled_fingers(conn, username) -> Result<Vec<String>, String>`; `has_enrolled` becomes a wrapper. `""` = calling user.
- `enroll(conn, finger, timeout, cancel, on_progress: impl FnMut(EnrollProgress)) -> EnrollResult`
  - Sequence: resolve owner (same `resolve_owner`), `GetDefaultDevice`, `Claim("")`, subscribe `EnrollStatus` (sender = owner, path = device), read `num-enroll-stages`, `EnrollStart(finger)`, loop.
  - `classify_enroll(result, done)`: `enroll-completed`→`Completed`; `enroll-stage-passed`→progress `StagePassed`; retry statuses (`enroll-retry-scan`, `-swipe-too-short`, `-finger-not-centered`, `-remove-and-retry`, other non-final) → progress `Retry(hint)`; `enroll-duplicate`→`Duplicate`; `enroll-data-full`, `enroll-failed`, `enroll-disconnected`, `enroll-unknown-error`, other final → `Failed(status)`.
  - Cleanup reuses `Session`, generalised from `verify_sent` to a `stop_method: Option<&'static str>` (`VerifyStop` / `EnrollStop`).
  - Same trust rule as verify (TRAY-13): `signal_is_trusted` takes the member name.
- Errors: method errors map to `EnrollResult::Unavailable(String)`; `PermissionDenied`/polkit dismissal → `NotAuthorized`; `AlreadyInUse` → `Busy`.

### `passkey-tpm-uv::mock` (extended)

`MockFprintd::enroll_results` scripted `EnrollStatus` list (default `[stage-passed, completed]`); `EnrollStart`/`EnrollStop` recorded in `MockCalls`; completing appends the finger to `enrolled`; `ListEnrolledFingers("")` answers for the claimed user; `num-enroll-stages` property.

### `crates/tray` (new, `passkey-tpm-tray`)

- `lib.rs` — pure, unit-tested: `Snapshot { reader: Reader, broker: Broker, key: VirtualKey }` (each starts as `Checking`), `Snapshot::health() -> Health { Checking | Ready | Problem(String) }`, menu-line helpers, `enroll_target()`, `next_finger`, `finger_label`, `EnrollTracker` (progress/result → notification text), `fingerprint_pixmap(size, rgb)` + `health_colour`.
- `probe.rs` — the three probes, each wrapped in `tokio::time::timeout(5 s)`.
- `main.rs` — `struct TrayApp { snapshot, enrolling, tx }` implementing `ksni::Tray` (id `passkey-tpm`, built-in fingerprint pixmap coloured by health — Adwaita has no `fingerprint` icon — status Active/NeedsAttention, tooltip, menu); command loop; notifications via `notify-rust` on one worker thread so progress stays ordered and replaces itself by id.
- Spawned with `assume_sni_available(true)` so starting before the panel doesn't exit.

## Decisions

- No new D-Bus surface on the broker: reachability uses `Introspect`, which the existing policy already allows.
- The tray never touches TPM or broker secrets; enrollment authority stays with fprintd's polkit action (`auth_self_keep` by default) — the shipped `50-passkey-tpm-fprintd.rules` doesn't change.
- `/usr/bin/passkey-tpm-tray` (user-launchable) + `/etc/xdg/autostart/passkey-tpm-tray.desktop`.

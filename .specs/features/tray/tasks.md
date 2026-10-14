# Tray Icon — Tasks

Gate per task: `cargo xtask fmt --check && cargo xtask clippy && cargo xtask test` (quick); final: `cargo xtask ci`.

| ID | What | Where | Depends | Reqs | Tests | Status |
|---|---|---|---|---|---|---|
| T1 | fprintd `enroll` + `enrolled_fingers`, generalised cleanup/trust; mock `EnrollStart/Stop/EnrollStatus` | `crates/uv/src/fprintd.rs`, `crates/uv/src/mock.rs`, `crates/uv/tests/fprintd.rs` | — | TRAY-09/10/11/13 | unit (classify_enroll, trust) + integration-dbus (mock: complete, duplicate, cancel → EnrollStop+Release, forged sender ignored) | Done |
| T2 | Crate skeleton `passkey-tpm-tray`; ksni dep; `deny.toml` Unlicense exception for ksni | `crates/tray/`, `deny.toml` | — | TRAY-15 | `cargo xtask deny` | Done |
| T3 | Pure model + probes | `crates/tray/src/lib.rs`, `crates/tray/src/probe.rs` | T1, T2 | TRAY-02/03/05/07/08 | unit (next_finger order/all-enrolled, health ordering, labels) | Done |
| T4 | ksni tray, menu, command loop, enroll notifications | `crates/tray/src/main.rs` | T3 | TRAY-01/04/06/08/10/12 | build + manual run against SNI host | Done |
| T5 | Packaging: desktop file, `xtask dist`, PKGBUILD, Fedora spec, debian rules, README | `packaging/`, `xtask/src/tasks/dist.rs`, `README.md` | T4 | TRAY-14 | `cargo xtask dist --destdir /tmp/x` lists the files; dist unit tests | Done |
| T6 | STATE/ROADMAP update | `.specs/project/` | T5 | — | — | Done |

## Results (2026-10-13)

- T1: `fprintd::enroll` / `enrolled_fingers`; 6 new integration tests (complete + progress, duplicate, data-full, polkit denied, busy, cancel/timeout cleanup, forged `EnrollStatus`) + `classify_enroll` unit test. Found and fixed: `device_description` called `StartServiceByName` unconditionally, which fails when fprintd runs without a `.service` file.
- T3: 9 unit tests (finger order, health ordering, menu lines, tracker, pixmap).
- T4: live on i3 (no reader/broker): `NeedsAttention`, tooltip "No fingerprint reader detected", no enroll item. E2E against `mock-fprintd` on a private system bus: menu `Event(clicked)` on "Enroll new fingerprint" → "Cancel enrollment (left index finger)" while running → "2 fingers enrolled" after.
- T5: `cargo xtask dist --destdir` installs both files; dist tests updated.
- Pending: UAT on KDE / GNOME+AppIndicator with a real reader and polkit agent (STATE todo).

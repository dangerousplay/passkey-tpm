# Tray Icon — Context (user decisions, 2026-10-13)

| # | Gray area | Decision | Why |
|---|---|---|---|
| D1 | SNI implementation | `ksni` 0.3 (zbus + tokio) with a crate-scoped `Unlicense` exception in `deny.toml` | Least code, same D-Bus stack as the rest; Unlicense is public-domain-equivalent and distro-acceptable |
| D2 | Placement | New crate/binary `passkey-tpm-tray`, started by XDG autostart | Agent stays headless; a tray crash or missing SNI host can't remove the virtual key |
| D3 | Finger choice | "Enroll new fingerprint" picks the next free finger automatically (fixed order, right index first) | Single click; no 10-item submenu |
| D4 | Status shown | Fingerprint reader, broker reachability, virtual key (agent unit), enrollment progress notifications | All four selected |

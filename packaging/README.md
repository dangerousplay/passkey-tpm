# Packaging files

Distribution-neutral integration files for passkey-tpm. Install paths:

| File | Destination |
|---|---|
| `systemd/passkey-tpm-uvd.service` | `/usr/lib/systemd/system/` |
| `systemd/passkey-tpm-agent.service` | `/usr/lib/systemd/user/` |
| `dbus/io.github.dangerousplay.PasskeyTpm1.conf` | `/usr/share/dbus-1/system.d/` |
| `dbus/io.github.dangerousplay.PasskeyTpm1.service` | `/usr/share/dbus-1/system-services/` |
| `polkit/50-passkey-tpm-fprintd.rules` | `/usr/share/polkit-1/rules.d/` |
| `udev/70-passkey-tpm-uhid.rules` | `/usr/lib/udev/rules.d/` |
| `sysusers/passkey-tpm.conf` | `/usr/lib/sysusers.d/` |
| `modules-load/passkey-tpm.conf` | `/usr/lib/modules-load.d/` (loads `uhid`) |

Binaries go to `/usr/libexec/passkey-tpm/` (Debian: `/usr/libexec` is fine since bookworm).
Users need no group membership: the broker is the only TPM client and the agent gets
`/dev/uhid` through `uaccess`.

The D-Bus name prefix `io.github.dangerousplay` is provisional.

## Building packages

All recipes install through `cargo xtask dist --destdir <root>`, so every distribution
ships the same files:

| Distribution | Recipe | Notes |
|---|---|---|
| Arch / AUR | `packaging/arch/PKGBUILD` | `--libexecdir /usr/lib` (Arch policy) |
| Fedora / COPR | `packaging/fedora/passkey-tpm.spec` | vendored crates for COPR; Source2 = `packaging/sysusers/passkey-tpm.conf` |
| Debian / Ubuntu PPA | `packaging/debian/` (copy to `debian/`) | cargo build; an archive upload would use debcargo-packaged crates |

`cargo xtask dist` (no `--destdir`) writes `target/dist/passkey-tpm-<version>.tar.gz`.

## Upstream binary packages

[`.goreleaser.yaml`](../.goreleaser.yaml) packages the same `cargo xtask dist` tree as `.deb`,
`.rpm` and Arch packages with nfpm (install scripts in [`nfpm/`](nfpm/)), plus checksums and
the source tarball. `cargo xtask release` builds a snapshot into `target/goreleaser/`; a `v*`
tag publishes a draft GitHub release with notes from `cargo xtask changelog --latest`
(git-cliff, [`cliff.toml`](../cliff.toml)). The `.deb` depends on Ubuntu 24.04 / Debian 13
library names.

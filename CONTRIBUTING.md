# Contributing to passkey-tpm

Design documents: [`.specs/`](.specs/) (project, roadmap, decisions in `STATE.md`), the
[ADRs](docs/adr/) and the [threat model](docs/threat-model.md).

## Architecture

```
browser / libfido2 / pam_u2f ──▶ passkey-tpm-agent (per user: uhid, prompts)
                                       │ system D-Bus
                                       ▼
                                passkey-tpm-uvd (broker: verified core, TPM, fprintd)
```

| Crate | Role |
|---|---|
| `passkey-tpm-core` | CTAP 2.1 state machine, Verus-verified |
| `passkey-tpm-wire` | CTAPHID framing and CBOR, Kani-checked |
| `passkey-tpm-tpm` | TPM policy model (ADR 0003) on tpm2-tss |
| `passkey-tpm-uv` | fprintd user verification |
| `passkey-tpm-transport-uhid` | virtual HID device |
| `passkey-tpm-provider-dbus` | broker D-Bus interface |
| `passkey-tpm-uvd` / `-agent` / `-cli` | broker, session agent, admin CLI |
| `passkey-tpm-testkit` | swtpm and fake-fprintd fixtures |

## Checks

Everything runs through `cargo xtask`; CI runs the same steps, one job each.

| Command | What it does |
|---|---|
| `cargo xtask fmt [--check]` | rustfmt |
| `cargo xtask clippy` | clippy with `-D warnings` |
| `cargo xtask deny` | licenses, advisories, bans, sources |
| `cargo xtask test` | test suite with pass count |
| `cargo xtask verus` | Verus proofs (downloads the pinned release) |
| `cargo xtask portability` | non-Linux build check |
| `cargo xtask ci [--full]` | the fast gate above; `--full` adds Kani and fuzzing |
| `cargo xtask kani` | Kani proofs (installs the pinned version) |
| `cargo xtask fuzz [--time N] [TARGET]` | cargo-fuzz targets |
| `cargo xtask vm` | Ubuntu 24.04 VM end-to-end suite (mkosi, swtpm, virtual fprintd) |
| `cargo xtask dist [--destdir DIR]` | install tree / source tarball used by every package |
| `cargo xtask changelog [--latest] [--output FILE]` | `CHANGELOG.md` with git-cliff |
| `cargo xtask release [--publish]` | GoReleaser packages (snapshot unless `--publish`) |

Requirements: rustup, `curl`, `unzip`, `sha256sum`, `libtss2-dev`, `pkg-config`; `swtpm` for
the TPM tests; `mkosi` and `qemu` for `cargo xtask vm`. All external tools are pinned in
[`tools/`](tools/) and checksum-verified on download. Testing tiers are described in
[`.specs/codebase/TESTING.md`](.specs/codebase/TESTING.md).

## Commits and releases

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
`perf:`, `security:`, `docs:`, ...); git-cliff groups them into the changelog and the GitHub
release notes. To release, push a signed `vX.Y.Z` tag: the `release` workflow runs the gate,
writes the notes and publishes a draft release with `.deb`, `.rpm` and Arch packages. See
[`packaging/README.md`](packaging/README.md) for distribution recipes.

Contributions are dual-licensed under MIT and Apache-2.0, as below.

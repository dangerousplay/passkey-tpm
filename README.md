# passkey-tpm

Passkeys (FIDO2/WebAuthn) for Linux, bound to your machine's TPM 2.0 and unlocked with
fingerprint, PIN, or other local verification methods. Distribution-agnostic and designed for
inclusion in Linux distributions.

> **Status: pre-alpha.** Not ready for use. Design and specifications live in [`.specs/`](.specs/).

## Goals

- Credentials that can't be used or extracted without the TPM and the user's verification,
  enforced by TPM policy rather than daemon logic ([ADR 0003](docs/adr/0003-tpm-policy-model.md)).
- A formally verified authenticator core (Verus), panic-free parsers (Kani) and continuous
  fuzzing ([ADR 0001](docs/adr/0001-rust-verified-core.md)).
- Works with today's clients through a virtual FIDO HID device, and with the freedesktop
  credential portal (credentialsd) as it matures ([ADR 0002](docs/adr/0002-provider-and-uhid.md)).

## Architecture

```
browser / libfido2 / pam_u2f ──▶ passkey-tpm-agent (per user: uhid, prompts)
                                       │ system D-Bus
                                       ▼
                                passkey-tpm-uvd (broker: verified core, TPM, fprintd)
```

See the [threat model](docs/threat-model.md).

## Development

All checks run through `cargo xtask`:

| Command | What it does |
|---|---|
| `cargo xtask fmt [--check]` | rustfmt |
| `cargo xtask clippy` | clippy with `-D warnings` |
| `cargo xtask deny` | licenses, advisories, bans, sources |
| `cargo xtask test` | test suite with pass count |
| `cargo xtask verus` | Verus proofs (downloads the pinned release) |
| `cargo xtask kani` | Kani proofs (installs the pinned version) |
| `cargo xtask fuzz [--time N] [TARGET]` | cargo-fuzz targets |
| `cargo xtask ci` | everything above, in CI order |

Requirements: rustup, `curl`, `unzip`, `sha256sum`. Integration tests will need `swtpm`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

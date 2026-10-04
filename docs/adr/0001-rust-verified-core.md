# ADR 0001: Rust with a formally verified core

- Status: Accepted
- Date: 2026-10-03

## Context

The predecessor (tpm-fido2-thinkpad-linux, Go) had software-only user verification, extractable
hmac-secret material and panics on malformed input. The Linux passkey ecosystem
(credentialsd, libwebauthn, zbus, tss-esapi) is written in Rust.

## Decision

Rewrite in Rust in a new repository. Security-critical state machines live in
`passkey-tpm-core` and are verified with Verus. Parsers and codecs live in `passkey-tpm-wire`
and are proven panic-free with Kani and fuzzed with cargo-fuzz. Everything else is an
imperative shell (tokio, zbus, tss-esapi, uhid). The core and wire crates forbid `unsafe`.
The core crate denies `unwrap`, `expect`, `panic` and unchecked indexing; the wire crate also
denies unchecked arithmetic.

## Consequences

- Toolchain pins: Rust 1.98.1 (required by Verus), Verus and `vstd` exact versions, Kani,
  cargo-fuzz and its nightly. They are bumped together.
- `vstd` becomes a build dependency, which distributions must package or we must make optional.
- Go code is frozen and serves only as a behavioural reference.

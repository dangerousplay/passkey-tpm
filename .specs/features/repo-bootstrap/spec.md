# Repo Bootstrap (M0) — Specification

**Milestone:** M0
**Scope:** Large (multi-component tooling, no product logic)
**Status:** Approved (derived from AD-001, AD-004, AD-005, AD-006)

## Goal

A new `passkey-tpm` repository whose pipeline is fully green and enforces every quality gate from day one, so feature work in M1 starts with verification already in place.

## Requirements

| ID | Requirement |
|---|---|
| BOOT-01 | Cargo workspace with crates `passkey-tpm-core` (Verus), `passkey-tpm-wire` (Kani: parsers/codecs), `-tpm`, `-uv`, `-transport-uhid`, `-provider-dbus`, `-uvd`, `-agent`, `-cli`, plus `xtask`. Stubs compile. |
| BOOT-02 | `rust-toolchain.toml` pinned to the Rust version supported by the pinned Verus release. Edition 2021+. |
| BOOT-03 | License `MIT OR Apache-2.0` (both files), NOTICE crediting psanford/tpm-fido, README, SECURITY.md. |
| BOOT-04 | `[workspace.lints]` with clippy `-D warnings`. `passkey-tpm-core` additionally denies `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects` and has `#![forbid(unsafe_code)]`. |
| BOOT-05 | `cargo xtask` alias. Subcommands: `fmt [--check]`, `clippy`, `test`, `deny`, `verus`, `kani`, `fuzz [--time N] [target]`, `build`, `ci`, `dist` (stub). Non-zero exit on failure. Prints test counts. |
| BOOT-06 | `deny.toml`: license allowlist, advisories = deny, `serde_cbor` banned, sources = crates.io only. `cargo xtask deny` passes. |
| BOOT-07 | Verus release and exact `vstd` pinned (`tools/verus.toml`). `cargo xtask verus` downloads or verifies the pinned binary by checksum and verifies the core crate. A trivial proof exists. |
| BOOT-08 | Kani pinned. `cargo xtask kani` runs the harnesses. A trivial harness exists. |
| BOOT-09 | cargo-fuzz set up. `cargo xtask fuzz --time 60` runs every target. A trivial target exists. |
| BOOT-10 | GitHub Actions: PR pipeline runs fmt → clippy → deny → test → verus → kani → fuzz smoke, each step as `cargo xtask <task>`. Nightly long fuzz. Tool caches. |
| BOOT-11 | `cargo xtask ci` runs the same sequence locally. |
| BOOT-12 | `docs/threat-model.md` (T1–T5 from tpm-policy-model spec) and `docs/adr/0001–0003` (Rust + verified core, provider + uhid, TPM policy model) committed. |
| BOOT-13 | `.specs/` moved from the Go repo into the new repo; Go repo README gets a frozen/security notice linking to the new repo. |

## Out of scope

- Product code beyond compiling stubs.
- ADR-004 (ctap-types vs passkey-types) — separate research task in M1.

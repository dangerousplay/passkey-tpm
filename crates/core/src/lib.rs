//! Formally verified CTAP 2.1 authenticator core for passkey-tpm.
//!
//! Everything security-relevant in this crate is written inside `verus!` blocks and
//! checked with `cargo xtask verus`. Plain `cargo build` erases the ghost code.
#![forbid(unsafe_code)]

pub mod ctap2;
pub mod ctaphid;
pub mod evidence;
pub mod gates;
pub mod pin_protocol;
pub mod pin_retries;
pub mod token;
pub mod tpm_iface;

//! Panic-free wire formats for passkey-tpm.
//!
//! Every decoder in this crate takes untrusted bytes. Kani harnesses (`cargo xtask kani`)
//! prove they never panic, and the same functions are exercised by cargo-fuzz targets.
#![forbid(unsafe_code)]

pub mod cbor;
pub mod credid;
pub mod gatestore;
pub mod reader;
pub mod resident;

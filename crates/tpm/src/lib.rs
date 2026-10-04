//! TPM 2.0 backend for passkey-tpm (ADR 0003): policy-bound credential keys and per-user gates.
#![forbid(unsafe_code)]

pub mod adapter;
pub mod credential;
pub mod credtag;
pub mod error;
pub mod fsutil;
pub mod gates;
pub mod health;
pub mod nvgate;
pub mod objects;
pub mod pin;
pub mod policy;
pub mod session;
pub mod sign;
pub mod srk;

pub use error::{Error, Result};

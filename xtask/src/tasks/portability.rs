use crate::runner::{cargo, exec, Result};

/// Crates that must stay OS-independent (AD-015): no Linux-only APIs.
pub const PORTABLE_CRATES: &[&str] = &["passkey-tpm-core", "passkey-tpm-wire"];
/// Non-Linux targets they are checked against.
pub const TARGETS: &[&str] = &["x86_64-unknown-freebsd"];

pub fn run(_args: &[String]) -> Result {
    for target in TARGETS {
        let mut cmd = cargo();
        cmd.args(["check", "--locked", "--target", target]);
        for krate in PORTABLE_CRATES {
            cmd.args(["-p", krate]);
        }
        exec(&mut cmd)?;
    }
    Ok(())
}

use std::path::PathBuf;
use std::process::Command;

use crate::runner::{cargo, exec, workspace_root, Result};
use crate::tools::{tools_dir, Pin};

/// Crates with `#[kani::proof]` harnesses.
const PROVED_CRATES: &[&str] = &["crates/wire"];

pub fn run(_args: &[String]) -> Result {
    let cargo_kani = install()?;
    for krate in PROVED_CRATES {
        let mut cmd = Command::new(&cargo_kani);
        cmd.arg("kani").current_dir(workspace_root().join(krate));
        exec(&mut cmd)?;
    }
    Ok(())
}

/// Installs the pinned `kani-verifier` into `target/tools/kani-<version>` and runs its setup.
fn install() -> Result<PathBuf> {
    let pin = Pin::load("kani")?;
    let version = pin.get("version")?;
    let root = tools_dir().join(format!("kani-{version}"));
    let cargo_kani = root.join("bin").join("cargo-kani");
    if !cargo_kani.exists() {
        exec(
            cargo()
                .args([
                    "install",
                    "--locked",
                    "kani-verifier",
                    "--version",
                    version,
                    "--root",
                ])
                .arg(&root),
        )?;
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    if !home.join(".kani").join(format!("kani-{version}")).exists() {
        exec(Command::new(&cargo_kani).arg("setup"))?;
    }
    Ok(cargo_kani)
}

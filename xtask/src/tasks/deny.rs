use std::path::PathBuf;
use std::process::Command;

use crate::runner::{cargo, exec, workspace_root, Result};
use crate::tools::{tools_dir, Pin};

pub fn run(_args: &[String]) -> Result {
    let cargo_deny = install()?;
    let mut cmd = Command::new(cargo_deny);
    cmd.current_dir(workspace_root())
        .args(["--locked", "check", "--show-stats"]);
    exec(&mut cmd)
}

fn install() -> Result<PathBuf> {
    let version = Pin::load("deny")?.get("version")?.to_owned();
    let root = tools_dir().join(format!("cargo-deny-{version}"));
    let bin = root.join("bin").join("cargo-deny");
    if !bin.exists() {
        exec(
            cargo()
                .args([
                    "install",
                    "--locked",
                    "cargo-deny",
                    "--version",
                    &version,
                    "--root",
                ])
                .arg(&root),
        )?;
    }
    Ok(bin)
}

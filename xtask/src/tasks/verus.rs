use std::path::PathBuf;
use std::process::Command;

use crate::runner::{exec, workspace_root, Error, Result};
use crate::tools::{fetch_verified, tools_dir, Pin};

/// Crates whose `verus!` code is verified.
const VERIFIED_CRATES: &[&str] = &["crates/core"];

pub fn run(_args: &[String]) -> Result {
    let bin_dir = install()?;
    for krate in VERIFIED_CRATES {
        let mut cmd = Command::new(bin_dir.join("cargo-verus"));
        cmd.current_dir(workspace_root().join(krate))
            .args(["verus", "verify", "--locked"]);
        cmd.env("PATH", prepend_path(&bin_dir));
        exec(&mut cmd)?;
    }
    Ok(())
}

/// Ensures the pinned Verus release is unpacked and returns its binary directory.
fn install() -> Result<PathBuf> {
    let pin = Pin::load("verus")?;
    let version = pin.get("version")?;
    let root = tools_dir().join(format!("verus-{version}"));
    let bin_dir = root.join("verus-x86-linux");
    if bin_dir.join("verus").exists() {
        return Ok(bin_dir);
    }
    let zip = tools_dir().join(format!("verus-{version}.zip"));
    fetch_verified(pin.get("url")?, pin.get("sha256")?, &zip)?;
    exec(
        Command::new("unzip")
            .args(["-q", "-o"])
            .arg(&zip)
            .arg("-d")
            .arg(&root),
    )?;
    if !bin_dir.join("verus").exists() {
        return Err(Error::Msg(format!(
            "unexpected archive layout in {}",
            zip.display()
        )));
    }
    Ok(bin_dir)
}

fn prepend_path(dir: &std::path::Path) -> std::ffi::OsString {
    let mut paths = vec![dir.to_path_buf()];
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(paths).unwrap_or_default()
}

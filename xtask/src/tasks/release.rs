//! `cargo xtask changelog [--latest] [--output FILE]` and `cargo xtask release [--publish]`,
//! wrapping pinned git-cliff and GoReleaser binaries.

use std::path::PathBuf;
use std::process::Command;

use crate::runner::{exec, workspace_root, Error, Result};
use crate::tools::{fetch_verified, tools_dir, Pin};

/// Downloads a pinned tool archive and extracts `binary` from it (once).
fn tool(name: &str, binary_in_archive: &str, strip: u32) -> Result<PathBuf> {
    let pin = Pin::load(name)?;
    let dir = tools_dir().join(format!("{name}-{}", pin.get("version")?));
    let bin = dir.join(name);
    if bin.exists() {
        return Ok(bin);
    }
    let archive = dir.join(format!("{name}.tar.gz"));
    fetch_verified(pin.get("url")?, pin.get("sha256")?, &archive)?;
    exec(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&dir)
            .arg(format!("--strip-components={strip}"))
            .arg(binary_in_archive),
    )?;
    Ok(bin)
}

fn git_cliff() -> Result<PathBuf> {
    let version = Pin::load("git-cliff")?.get("version")?.to_owned();
    tool("git-cliff", &format!("git-cliff-{version}/git-cliff"), 1)
}

fn goreleaser() -> Result<PathBuf> {
    tool("goreleaser", "goreleaser", 0)
}

/// Arguments for git-cliff: offline unless a GitHub token is available.
fn cliff_args(args: &[String], has_token: bool) -> Result<Vec<String>> {
    let mut out = vec!["--config".to_owned(), "cliff.toml".to_owned()];
    if !has_token {
        out.push("--offline".to_owned());
    }
    let mut output = Some("CHANGELOG.md".to_owned());
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--latest" => {
                out.extend([
                    "--latest".to_owned(),
                    "--strip".to_owned(),
                    "header".to_owned(),
                ]);
                output = None; // release notes go to stdout unless --output is given
            }
            "--output" => {
                let file = it
                    .next()
                    .ok_or_else(|| Error::Msg("--output needs a file".into()))?;
                output = Some(file.clone());
            }
            other => return Err(Error::Msg(format!("unexpected argument `{other}`"))),
        }
    }
    if let Some(file) = output {
        out.extend(["--output".to_owned(), file]);
    }
    Ok(out)
}

pub fn changelog(args: &[String]) -> Result {
    let has_token = std::env::var_os("GITHUB_TOKEN").is_some();
    let mut cmd = Command::new(git_cliff()?);
    cmd.current_dir(workspace_root())
        .args(cliff_args(args, has_token)?);
    exec(&mut cmd)
}

/// Arguments for GoReleaser: a local, unsigned snapshot unless `--publish` (which signs
/// with keyless cosign and needs a CI OIDC token); other arguments (e.g.
/// `--release-notes FILE`) pass through.
fn goreleaser_args(args: &[String]) -> Vec<String> {
    let mut out = vec!["release".to_owned(), "--clean".to_owned()];
    if !args.iter().any(|a| a == "--publish") {
        out.extend(["--snapshot".to_owned(), "--skip=publish,sign".to_owned()]);
    }
    out.extend(args.iter().filter(|a| *a != "--publish").cloned());
    out
}

pub fn release(args: &[String]) -> Result {
    let mut cmd = Command::new(goreleaser()?);
    cmd.current_dir(workspace_root())
        .args(goreleaser_args(args));
    exec(&mut cmd)
}

#[cfg(test)]
mod tests {
    use super::{cliff_args, goreleaser_args};

    #[test]
    fn release_is_a_snapshot_unless_published() {
        assert_eq!(
            goreleaser_args(&[]),
            s(&["release", "--clean", "--snapshot", "--skip=publish,sign"])
        );
        assert_eq!(
            goreleaser_args(&s(&["--publish", "--release-notes", "n.md"])),
            s(&["release", "--clean", "--release-notes", "n.md"])
        );
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn changelog_defaults_to_offline_full_file() {
        assert_eq!(
            cliff_args(&[], false).unwrap(),
            s(&[
                "--config",
                "cliff.toml",
                "--offline",
                "--output",
                "CHANGELOG.md"
            ])
        );
    }

    #[test]
    fn latest_notes_use_github_when_a_token_exists() {
        assert_eq!(
            cliff_args(&s(&["--latest", "--output", "notes.md"]), true).unwrap(),
            s(&[
                "--config",
                "cliff.toml",
                "--latest",
                "--strip",
                "header",
                "--output",
                "notes.md"
            ])
        );
    }
}

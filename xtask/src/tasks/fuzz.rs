use std::path::PathBuf;
use std::process::Command;

use crate::runner::{cargo, exec, workspace_root, Error, Result};
use crate::tools::{tools_dir, Pin};

/// `cargo xtask fuzz [--time SECONDS] [TARGET]` runs each target (or just TARGET) for SECONDS.
pub fn run(args: &[String]) -> Result {
    let opts = Options::parse(args)?;
    let pin = Pin::load("fuzz")?;
    let cargo_fuzz = install(pin.get("version")?)?;
    let toolchain = pin.get("toolchain")?;

    let targets = match opts.target {
        Some(t) => vec![t],
        None => list_targets(&cargo_fuzz, toolchain)?,
    };
    for target in targets {
        exec(
            fuzz_cmd(&cargo_fuzz, toolchain)
                .args(["run", &target, "--"])
                .arg(format!("-max_total_time={}", opts.seconds)),
        )?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    seconds: u32,
    target: Option<String>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut opts = Options {
            seconds: 60,
            target: None,
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            if arg == "--time" {
                let value = it
                    .next()
                    .ok_or_else(|| Error::Msg("--time needs a value".into()))?;
                opts.seconds = value
                    .parse()
                    .map_err(|_| Error::Msg(format!("invalid --time value `{value}`")))?;
            } else if opts.target.is_none() && !arg.starts_with('-') {
                opts.target = Some(arg.clone());
            } else {
                return Err(Error::Msg(format!("unexpected argument `{arg}`")));
            }
        }
        Ok(opts)
    }
}

fn list_targets(cargo_fuzz: &PathBuf, toolchain: &str) -> Result<Vec<String>> {
    let out = fuzz_cmd(cargo_fuzz, toolchain)
        .arg("list")
        .output()
        .map_err(|source| Error::Spawn {
            program: "cargo-fuzz".into(),
            source,
        })?;
    if !out.status.success() {
        return Err(Error::Failed {
            program: "cargo fuzz list".into(),
            code: out.status.code(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect())
}

/// `cargo-fuzz fuzz` on the pinned nightly. cargo-fuzz runs `cargo` from PATH, and the
/// rustup proxy picks the toolchain from `RUSTUP_TOOLCHAIN`.
fn fuzz_cmd(cargo_fuzz: &PathBuf, toolchain: &str) -> Command {
    let mut cmd = Command::new(cargo_fuzz);
    cmd.current_dir(workspace_root())
        .env("RUSTUP_TOOLCHAIN", toolchain)
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .arg("fuzz");
    cmd
}

fn install(version: &str) -> Result<PathBuf> {
    let root = tools_dir().join(format!("cargo-fuzz-{version}"));
    let bin = root.join("bin").join("cargo-fuzz");
    if !bin.exists() {
        exec(
            cargo()
                .args([
                    "install",
                    "--locked",
                    "cargo-fuzz",
                    "--version",
                    version,
                    "--root",
                ])
                .arg(&root),
        )?;
    }
    Ok(bin)
}

#[cfg(test)]
mod tests {
    use super::Options;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn defaults_to_sixty_seconds_all_targets() {
        assert_eq!(
            Options::parse(&[]).unwrap(),
            Options {
                seconds: 60,
                target: None
            }
        );
    }

    #[test]
    fn parses_time_and_target() {
        let opts = Options::parse(&args(&["--time", "5", "wire_reader"])).unwrap();
        assert_eq!(
            opts,
            Options {
                seconds: 5,
                target: Some("wire_reader".into())
            }
        );
    }

    #[test]
    fn rejects_bad_time() {
        assert!(Options::parse(&args(&["--time", "soon"])).is_err());
    }
}

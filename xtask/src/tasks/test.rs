use std::process::Stdio;

use crate::runner::{cargo, Error, Result};

pub fn run(args: &[String]) -> Result {
    require_swtpm()?;
    let mut cmd = cargo();
    cmd.args(["test", "--workspace", "--locked"]).args(args);
    cmd.stdout(Stdio::piped());
    eprintln!("$ cargo test --workspace ...");
    let output = cmd.output().map_err(|source| Error::Spawn {
        program: "cargo test".into(),
        source,
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");
    let (passed, failed) = count(&stdout);
    println!("xtask test: {passed} passed, {failed} failed");
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Failed {
            program: "cargo test".into(),
            code: output.status.code(),
        })
    }
}

/// TPM integration tests start private `swtpm` instances.
fn require_swtpm() -> Result {
    match std::process::Command::new("swtpm").arg("--version").output() {
        Ok(out) if out.status.success() => Ok(()),
        _ => Err(Error::Msg(
            "swtpm not found: install it (Arch: pacman -S swtpm, Debian/Ubuntu: apt install swtpm, Fedora: dnf install swtpm)"
                .into(),
        )),
    }
}

/// Sums the `test result:` lines libtest prints for every test binary.
fn count(stdout: &str) -> (u64, u64) {
    let mut totals = (0, 0);
    for line in stdout.lines().filter(|l| l.starts_with("test result:")) {
        totals.0 += field(line, " passed");
        totals.1 += field(line, " failed");
    }
    totals
}

fn field(line: &str, suffix: &str) -> u64 {
    line.split(';')
        .find_map(|part| {
            part.trim()
                .trim_start_matches("test result: ok. ")
                .trim_start_matches("test result: FAILED. ")
                .strip_suffix(suffix)?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::count;

    #[test]
    fn sums_result_lines() {
        let out = "test result: ok. 3 passed; 0 failed; 0 ignored\nnoise\ntest result: FAILED. 2 passed; 1 failed; 0 ignored\n";
        assert_eq!(count(out), (5, 1));
    }
}

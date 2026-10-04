//! `cargo xtask vm [--no-build] [--timeout SECONDS]`: end-to-end scenarios in an mkosi VM
//! with a throwaway swtpm TPM and libfprint's virtual fingerprint device (AD-014).

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::runner::{exec, workspace_root, Error, Result};
use crate::tools::{tools_dir, Pin};

const RESULT_PREFIX: &str = "PASSKEY_TPM_E2E_RESULT=";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    build: bool,
    timeout: Duration,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut opts = Options {
            build: true,
            timeout: Duration::from_secs(1500),
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--no-build" => opts.build = false,
                "--timeout" => {
                    let v = it
                        .next()
                        .ok_or_else(|| Error::Msg("--timeout needs seconds".into()))?;
                    opts.timeout = Duration::from_secs(
                        v.parse()
                            .map_err(|_| Error::Msg(format!("invalid --timeout `{v}`")))?,
                    );
                }
                other => return Err(Error::Msg(format!("unexpected argument `{other}`"))),
            }
        }
        Ok(opts)
    }
}

/// Interprets the runner's result line, e.g. `PASSKEY_TPM_E2E_RESULT=PASS tpm-status=PASS ...`.
fn verdict(line: &str) -> Option<bool> {
    let rest = line.split(RESULT_PREFIX).nth(1)?;
    match rest.split_whitespace().next()? {
        "PASS" => Some(true),
        "FAIL" => Some(false),
        _ => None,
    }
}

/// Installs the pinned mkosi into a virtualenv under target/tools.
fn mkosi() -> Result<PathBuf> {
    let version = Pin::load("mkosi")?.get("version")?.to_owned();
    let venv = tools_dir().join(format!("mkosi-{version}"));
    let bin = venv.join("bin").join("mkosi");
    if !bin.exists() {
        exec(Command::new("python3").args(["-m", "venv"]).arg(&venv))?;
        exec(
            Command::new(venv.join("bin").join("pip"))
                .args(["install", "-q"])
                .arg(format!("git+https://github.com/systemd/mkosi@{version}")),
        )?;
    }
    Ok(bin)
}

pub fn run(args: &[String]) -> Result {
    let opts = Options::parse(args)?;
    let mkosi = mkosi()?;
    let dir = workspace_root().join("tests").join("vm");
    let report = workspace_root().join("target").join("vm").join("report");
    let _ = std::fs::remove_dir_all(&report);
    std::fs::create_dir_all(&report)
        .map_err(|e| Error::Msg(format!("{}: {e}", report.display())))?;
    if opts.build {
        exec(Command::new(&mkosi).current_dir(&dir).args(["-f", "build"]))?;
    }
    let mut child = Command::new(&mkosi)
        .current_dir(&dir)
        .arg("qemu")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|source| Error::Spawn {
            program: "mkosi qemu".into(),
            source,
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Msg("no VM console".into()))?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout)
            .lines()
            .map_while(std::result::Result::ok)
        {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let deadline = Instant::now() + opts.timeout;
    let mut outcome = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) => {
                println!("{line}");
                if let Some(v) = verdict(&line) {
                    outcome = Some(v);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    // The JUnit report is authoritative; the console marker covers a missing report mount.
    let junit = std::fs::read_to_string(report.join("junit.xml")).ok();
    let summary = junit.as_deref().and_then(junit_summary);
    if let Some(sum) = &summary {
        println!(
            "\nVM e2e: {} tests, {} failed, {} errors, {} skipped. Report: {}",
            sum.tests,
            sum.failures,
            sum.errors,
            sum.skipped,
            report.join("report.html").display()
        );
        for name in junit.as_deref().map(failed_tests).unwrap_or_default() {
            println!("  FAILED {name}");
        }
    }
    match (summary, outcome) {
        (Some(sum), _) if sum.tests > 0 && sum.failures == 0 && sum.errors == 0 => Ok(()),
        (Some(_), _) => Err(Error::Msg("VM scenarios failed".into())),
        (None, Some(true)) => Ok(()),
        (None, Some(false)) => Err(Error::Msg("VM scenarios failed (no JUnit report)".into())),
        (None, None) => Err(Error::Msg(
            "VM produced no result before exiting or timing out".into(),
        )),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct JunitSummary {
    tests: u32,
    failures: u32,
    errors: u32,
    skipped: u32,
}

fn attr(tag: &str, name: &str) -> Option<u32> {
    let start = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    let rest = tag.get(start..)?;
    rest.get(..rest.find('"')?)?.parse().ok()
}

/// Totals from the first `<testsuite ...>` element of a pytest JUnit report.
fn junit_summary(xml: &str) -> Option<JunitSummary> {
    let start = xml.find("<testsuite ")?;
    let tag = xml.get(start..start + xml.get(start..)?.find('>')?)?;
    Some(JunitSummary {
        tests: attr(tag, "tests")?,
        failures: attr(tag, "failures").unwrap_or(0),
        errors: attr(tag, "errors").unwrap_or(0),
        skipped: attr(tag, "skipped").unwrap_or(0),
    })
}

/// `classname::name` of every test case with a <failure> or <error>.
fn failed_tests(xml: &str) -> Vec<String> {
    xml.split("<testcase ")
        .skip(1)
        .filter(|case| {
            let body = case.split("</testcase>").next().unwrap_or("");
            body.contains("<failure") || body.contains("<error")
        })
        .filter_map(|case| {
            let get = |k: &str| {
                // Leading space: `name=` must not match inside `classname=`.
                let start = format!(" {case}").find(&format!(" {k}=\""))? + k.len() + 2;
                case.get(start..)
                    .and_then(|r| r.get(..r.find('"')?))
                    .map(str::to_owned)
            };
            Some(format!("{}::{}", get("classname")?, get("name")?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verdict_lines() {
        assert_eq!(
            verdict("[  12.3] run[1]: PASSKEY_TPM_E2E_RESULT=PASS a=PASS"),
            Some(true)
        );
        assert_eq!(verdict("PASSKEY_TPM_E2E_RESULT=FAIL a=FAIL"), Some(false));
        assert_eq!(verdict("PASSKEY_TPM_E2E_CHECK a=PASS"), None);
        assert_eq!(verdict("PASSKEY_TPM_E2E_RESULT="), None);
    }

    #[test]
    fn reads_junit_totals_and_failures() {
        let xml = r#"<?xml version="1.0"?><testsuites><testsuite name="pytest" errors="0" failures="1" skipped="2" tests="38" time="9.1"><testcase classname="tests.test_40_isolation" name="test_bob" time="1"><failure message="x">boom</failure></testcase><testcase classname="tests.test_00_system" name="test_ok" time="0"/></testsuite></testsuites>"#;
        assert_eq!(
            junit_summary(xml),
            Some(JunitSummary {
                tests: 38,
                failures: 1,
                errors: 0,
                skipped: 2
            })
        );
        assert_eq!(
            failed_tests(xml),
            vec!["tests.test_40_isolation::test_bob".to_owned()]
        );
        assert_eq!(junit_summary("<nope/>"), None);
    }

    #[test]
    fn parses_options() {
        let o = Options::parse(&["--no-build".into(), "--timeout".into(), "60".into()]).unwrap();
        assert_eq!(
            o,
            Options {
                build: false,
                timeout: Duration::from_secs(60)
            }
        );
        assert!(Options::parse(&["--timeout".into(), "x".into()]).is_err());
    }
}

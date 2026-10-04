use std::time::Instant;

use crate::runner::{Error, Result};

/// The fast pipeline run on every change: lints, unit/integration tests and Verus.
pub const STEPS: &[(&str, &[&str])] = &[
    ("fmt", &["--check"]),
    ("clippy", &[]),
    ("deny", &[]),
    ("test", &[]),
    ("verus", &[]),
    ("portability", &[]),
];

/// Slow checks added by `cargo xtask ci --full` (and run nightly in CI).
pub const SLOW_STEPS: &[(&str, &[&str])] = &[("kani", &[]), ("fuzz", &["--time", "60"])];

pub fn run(args: &[String]) -> Result {
    let full = args.iter().any(|a| a == "--full");
    let mut summary = Vec::new();
    let mut failure = None;
    let steps = STEPS
        .iter()
        .chain(if full { SLOW_STEPS.iter() } else { [].iter() });
    for (name, args) in steps {
        let task = super::find(name).ok_or_else(|| Error::Msg(format!("unknown step `{name}`")))?;
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let started = Instant::now();
        let result = (task.run)(&args);
        let ok = result.is_ok();
        summary.push((*name, ok, started.elapsed().as_secs()));
        if let Err(err) = result {
            failure = Some(Error::Msg(format!("step `{name}` failed: {err}")));
            break;
        }
    }
    println!("\nxtask ci summary:");
    for (name, ok, secs) in &summary {
        println!(
            "  {:<8} {:<4} {secs:>5}s",
            name,
            if *ok { "ok" } else { "FAIL" }
        );
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::{SLOW_STEPS, STEPS};

    #[test]
    fn pipeline_order_is_cheap_to_expensive() {
        let names: Vec<&str> = STEPS.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            ["fmt", "clippy", "deny", "test", "verus", "portability"]
        );
        let slow: Vec<&str> = SLOW_STEPS.iter().map(|(n, _)| *n).collect();
        assert_eq!(slow, ["kani", "fuzz"]);
    }

    #[test]
    fn every_step_is_a_registered_task() {
        for (name, _) in STEPS.iter().chain(SLOW_STEPS) {
            assert!(crate::tasks::find(name).is_some(), "{name} not registered");
        }
    }
}

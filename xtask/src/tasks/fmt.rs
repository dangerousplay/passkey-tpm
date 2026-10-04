use crate::runner::{cargo, exec, Result};

pub fn run(args: &[String]) -> Result {
    let mut cmd = cargo();
    cmd.args(["fmt", "--all"]);
    if args.iter().any(|a| a == "--check") {
        cmd.arg("--check");
    }
    exec(&mut cmd)
}

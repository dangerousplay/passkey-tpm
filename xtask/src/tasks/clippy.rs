use crate::runner::{cargo, exec, Result};

pub fn run(_args: &[String]) -> Result {
    exec(cargo().args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))
}

use crate::runner::{cargo, exec, Result};

pub fn run(_args: &[String]) -> Result {
    exec(cargo().args(["build", "--workspace", "--all-targets", "--locked"]))
}

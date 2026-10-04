//! Developer and CI task runner for passkey-tpm. Run `cargo xtask help`.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod runner;
mod tasks;
mod tools;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((name, rest)) = args.split_first() else {
        tasks::print_help();
        return ExitCode::FAILURE;
    };
    if name == "help" || name == "--help" || name == "-h" {
        tasks::print_help();
        return ExitCode::SUCCESS;
    }
    let Some(task) = tasks::find(name) else {
        eprintln!("xtask: unknown task `{name}`");
        tasks::print_help();
        return ExitCode::FAILURE;
    };
    match (task.run)(rest) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask {name}: {err}");
            ExitCode::FAILURE
        }
    }
}

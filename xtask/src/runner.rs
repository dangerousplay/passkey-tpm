//! Process helpers shared by all tasks.

use std::fmt;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug)]
pub enum Error {
    Spawn {
        program: String,
        source: std::io::Error,
    },
    Failed {
        program: String,
        code: Option<i32>,
    },
    Msg(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { program, source } => write!(f, "failed to start `{program}`: {source}"),
            Self::Failed {
                program,
                code: Some(code),
            } => {
                write!(f, "`{program}` exited with status {code}")
            }
            Self::Failed {
                program,
                code: None,
            } => write!(f, "`{program}` was killed by a signal"),
            Self::Msg(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T = ()> = std::result::Result<T, Error>;

fn program_name(cmd: &Command) -> String {
    let program = std::path::Path::new(cmd.get_program());
    let mut name = program
        .file_name()
        .unwrap_or(program.as_os_str())
        .to_string_lossy()
        .into_owned();
    for arg in cmd.get_args().take(2) {
        name.push(' ');
        name.push_str(&arg.to_string_lossy());
    }
    name
}

/// Runs `cmd` with inherited stdio and turns a non-zero exit into an error.
pub fn exec(cmd: &mut Command) -> Result {
    let program = program_name(cmd);
    eprintln!("$ {program} ...");
    let status = cmd.status().map_err(|source| Error::Spawn {
        program: program.clone(),
        source,
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Failed {
            program,
            code: status.code(),
        })
    }
}

/// A `cargo` command rooted at the workspace.
pub fn cargo() -> Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root());
    cmd
}

pub fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map_or(manifest_dir.clone(), PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_ok() {
        assert!(exec(&mut Command::new("true")).is_ok());
    }

    #[test]
    fn non_zero_exit_is_error_with_code() {
        let err = exec(Command::new("sh").args(["-c", "exit 3"])).unwrap_err();
        assert!(matches!(err, Error::Failed { code: Some(3), .. }), "{err}");
    }

    #[test]
    fn missing_program_is_spawn_error() {
        let err = exec(&mut Command::new("passkey-tpm-definitely-missing")).unwrap_err();
        assert!(matches!(err, Error::Spawn { .. }), "{err}");
    }
}

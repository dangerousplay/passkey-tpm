//! PIN entry through zenity or kdialog (the tray has no GUI toolkit of its own). The PINs
//! come back on the helper's stdout, never on a command line.

use std::process::Stdio;

use tokio::process::Command;
use zeroize::Zeroizing;

/// Field separator for zenity's form output; a PIN can't contain it (see
/// [`crate::pin::check_new_pin`], which also rejects NUL).
const SEPARATOR: &str = "\u{1f}";

/// What the user typed. Empty `current` when it wasn't asked for.
#[derive(Debug)]
pub struct PinEntry {
    /// The current PIN (change only).
    pub current: Zeroizing<String>,
    /// The new PIN.
    pub new: Zeroizing<String>,
    /// The new PIN again.
    pub confirm: Zeroizing<String>,
}

/// Why no PIN was entered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogError {
    /// The user closed or cancelled the dialog.
    Cancelled,
    /// Neither zenity nor kdialog is installed.
    NoHelper,
    /// The helper failed.
    Failed(String),
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

async fn output(cmd: &mut Command) -> Result<Zeroizing<String>, DialogError> {
    let out = cmd
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .await
        .map_err(|e| DialogError::Failed(e.to_string()))?;
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        return Err(DialogError::Cancelled);
    }
    let text = Zeroizing::new(
        String::from_utf8(stdout.to_vec()).map_err(|_| DialogError::Failed("not UTF-8".into()))?,
    );
    Ok(Zeroizing::new(
        text.strip_suffix('\n').unwrap_or(&text).to_owned(),
    ))
}

/// Splits zenity's form output into exactly `n` fields.
fn fields(text: &str, n: usize) -> Result<Vec<Zeroizing<String>>, DialogError> {
    let parts: Vec<Zeroizing<String>> = text
        .split(SEPARATOR)
        .map(|s| Zeroizing::new(s.to_owned()))
        .collect();
    if parts.len() == n {
        Ok(parts)
    } else {
        Err(DialogError::Failed(format!(
            "expected {n} fields, got {}",
            parts.len()
        )))
    }
}

/// Asks for a new PIN (twice) and, if `change`, the current one first.
///
/// # Errors
///
/// [`DialogError`] if the user cancels or no helper is available.
pub async fn ask(change: bool) -> Result<PinEntry, DialogError> {
    let title = if change { "Change PIN" } else { "Set PIN" };
    let text = "PIN for passkeys on this computer (at least 4 characters)";
    if on_path("zenity") {
        let mut cmd = Command::new("zenity");
        cmd.args(["--forms", "--title", title, "--text", text])
            .arg(format!("--separator={SEPARATOR}"));
        if change {
            cmd.arg("--add-password=Current PIN");
        }
        cmd.args(["--add-password=New PIN", "--add-password=Confirm new PIN"]);
        let out = output(&mut cmd).await?;
        let mut f = fields(&out, if change { 3 } else { 2 })?.into_iter();
        let current = if change { f.next() } else { None };
        let (Some(new), Some(confirm)) = (f.next(), f.next()) else {
            return Err(DialogError::Failed("missing field".into()));
        };
        return Ok(PinEntry {
            current: current.unwrap_or_default(),
            new,
            confirm,
        });
    }
    if on_path("kdialog") {
        let ask_one = |label: &str| {
            let mut cmd = Command::new("kdialog");
            cmd.args(["--title", title, "--password", label]);
            cmd
        };
        let current = if change {
            output(&mut ask_one("Current PIN")).await?
        } else {
            Zeroizing::default()
        };
        let new = output(&mut ask_one(text)).await?;
        let confirm = output(&mut ask_one("Confirm new PIN")).await?;
        return Ok(PinEntry {
            current,
            new,
            confirm,
        });
    }
    Err(DialogError::NoHelper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_form_fields() {
        let f = fields(&format!("12|34{SEPARATOR}5678"), 2).unwrap();
        assert_eq!(f[0].as_str(), "12|34");
        assert_eq!(f[1].as_str(), "5678");
        assert!(fields("1234", 2).is_err());
    }
}

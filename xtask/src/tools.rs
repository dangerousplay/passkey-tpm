//! Pinned external tools described by `tools/<name>.toml` (flat `key = "value"` files).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::runner::{exec, workspace_root, Error, Result};

#[derive(Debug)]
pub struct Pin(BTreeMap<String, String>);

impl Pin {
    pub fn load(name: &str) -> Result<Self> {
        let path = workspace_root().join("tools").join(format!("{name}.toml"));
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Msg(format!("cannot read {}: {e}", path.display())))?;
        parse(&text).map(Pin)
    }

    pub fn get(&self, key: &str) -> Result<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| Error::Msg(format!("missing key `{key}` in tool pin")))
    }
}

fn parse(text: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error::Msg(format!("line {}: expected key = \"value\"", lineno + 1)))?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or_else(|| Error::Msg(format!("line {}: value must be quoted", lineno + 1)))?;
        map.insert(key.trim().to_owned(), value.to_owned());
    }
    Ok(map)
}

/// Directory for downloaded tools, inside the workspace target dir.
pub fn tools_dir() -> PathBuf {
    workspace_root().join("target").join("tools")
}

/// Downloads `url` to `dest`, verifying its sha256. Reuses an existing file with a matching hash.
pub fn fetch_verified(url: &str, sha256: &str, dest: &Path) -> Result {
    if dest.exists() && sha256_of(dest)? == sha256 {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Msg(format!("cannot create {}: {e}", parent.display())))?;
    }
    exec(
        Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--output",
            ])
            .arg(dest)
            .arg(url),
    )?;
    let actual = sha256_of(dest)?;
    if actual != sha256 {
        let _ = std::fs::remove_file(dest);
        return Err(Error::Msg(format!(
            "checksum mismatch for {url}: expected {sha256}, got {actual}"
        )));
    }
    Ok(())
}

fn sha256_of(path: &Path) -> Result<String> {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|source| Error::Spawn {
            program: "sha256sum".into(),
            source,
        })?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::Msg(format!(
                "sha256sum produced no output for {}",
                path.display()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_flat_pins() {
        let map = parse("# c\nversion = \"1.2\"\n\nurl = \"https://x/y\"\n").unwrap();
        assert_eq!(map["version"], "1.2");
        assert_eq!(map["url"], "https://x/y");
    }

    #[test]
    fn fetch_rejects_checksum_mismatch_and_removes_file() {
        let dir = std::env::temp_dir().join(format!("xtask-fetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        std::fs::write(&src, b"payload").unwrap();
        let dest = dir.join("dest.bin");
        let url = format!("file://{}", src.display());
        let err = super::fetch_verified(&url, &"0".repeat(64), &dest).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
        assert!(!dest.exists());
        // sha256("payload")
        let good = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5";
        super::fetch_verified(&url, good, &dest).unwrap();
        assert!(dest.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_unquoted_values() {
        assert!(parse("version = 1.2").is_err());
    }
}

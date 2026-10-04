//! Crash-safe file replacement for broker state.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Atomically replaces `path` with `contents`, readable only by the owner (mode 0600).
///
/// Writes a temporary file in the same directory, fsyncs it, renames it over `path`, then
/// fsyncs the directory. Readers see either the old or the new file, never a partial one.
/// On error the temporary file this call created is removed; a temporary file that already
/// existed is left alone.
///
/// # Errors
/// Any I/O error (`AlreadyExists` if the temporary file exists); `path` is left unchanged
/// unless only the final directory fsync failed.
pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = dir.join(tmp_name);

    // If the temp file already exists (another writer, or a leftover), it isn't ours to
    // delete: fail without touching it (HARD-19).
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let result = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("passkey-tpm-fsutil-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn replaces_contents_with_private_mode() {
        let dir = scratch("replace");
        let path = dir.join("gates.v1");
        write_atomic(&path, b"old").unwrap();
        write_atomic(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "no temp files left");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_rename_keeps_old_file_and_cleans_up() {
        let dir = scratch("fail");
        let path = dir.join("gates.v1");
        write_atomic(&path, b"old").unwrap();
        // Renaming a file over a non-empty directory fails after the temp file is written.
        let blocker = dir.join("blocked");
        fs::create_dir_all(blocker.join("child")).unwrap();
        assert!(write_atomic(&blocker, b"new").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp file not cleaned up");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_temp_file_is_not_deleted() {
        // HARD-19: another writer's temp file must survive our failed attempt.
        let dir = scratch("exists");
        let path = dir.join("gates.v1");
        let theirs = dir.join(format!(".gates.v1.tmp.{}", std::process::id()));
        fs::write(&theirs, b"theirs").unwrap();
        let err = write_atomic(&path, b"new").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&theirs).unwrap(), b"theirs");
        assert!(!path.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}

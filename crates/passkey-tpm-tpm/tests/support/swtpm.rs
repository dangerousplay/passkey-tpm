//! Per-test software TPM. Each [`Swtpm`] owns a private `swtpm` process and state directory,
//! so integration tests can run in parallel.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

pub struct Swtpm {
    child: Child,
    port: u16,
    state_dir: PathBuf,
}

impl Swtpm {
    /// Starts a fresh, already-initialised (TPM2_Startup(CLEAR)) software TPM.
    pub fn start() -> Self {
        for _ in 0..20 {
            if let Some(tpm) = Self::try_start() {
                return tpm;
            }
        }
        panic!("could not start swtpm after 20 attempts (is `swtpm` installed?)");
    }

    fn try_start() -> Option<Self> {
        let port = reserve_port_pair()?;
        let state_dir =
            std::env::temp_dir().join(format!("passkey-tpm-swtpm-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&state_dir).ok()?;
        let child = Command::new("swtpm")
            .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
            .arg("--server")
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
            .arg("--tpmstate")
            .arg(format!("dir={}", state_dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect(
                "failed to spawn swtpm; install it (e.g. `pacman -S swtpm`, `apt install swtpm`)",
            );
        let mut tpm = Swtpm {
            child,
            port,
            state_dir,
        };
        if tpm.wait_ready(Duration::from_secs(5)) {
            Some(tpm)
        } else {
            // Port collision or slow start: drop kills the process; retry with new ports.
            let _ = tpm.child.kill();
            None
        }
    }

    fn wait_ready(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return false;
            }
            let data = TcpStream::connect(("127.0.0.1", self.port)).is_ok();
            let ctrl = TcpStream::connect(("127.0.0.1", self.port + 1)).is_ok();
            if data && ctrl {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    pub fn tcti(&self) -> TctiNameConf {
        TctiNameConf::from_str(&format!("swtpm:host=127.0.0.1,port={}", self.port))
            .expect("valid swtpm TCTI")
    }

    pub fn context(&self) -> Context {
        Context::new(self.tcti()).expect("connect to swtpm")
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

/// Finds a port `p` such that `p` and `p + 1` are both free right now.
fn reserve_port_pair() -> Option<u16> {
    for _ in 0..50 {
        let first = TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let port = first.local_addr().ok()?.port();
        let next = port.checked_add(1)?;
        if TcpListener::bind(("127.0.0.1", next)).is_ok() {
            return Some(port);
        }
    }
    None
}

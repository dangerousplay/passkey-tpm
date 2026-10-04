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

    /// `TPM2_DictionaryAttackParameters` with the (empty) lockout authorisation, sent as a raw
    /// command because tss-esapi 7.7 has no binding (B-002). swtpm defaults to maxTries 3.
    /// Call it while no [`Context`] is connected: swtpm serves one connection at a time.
    #[allow(dead_code)] // Only some test binaries change the DA parameters.
    pub fn set_da_parameters(&self, max_tries: u32, recovery_s: u32, lockout_recovery_s: u32) {
        use std::io::{Read, Write};
        use tss_esapi::constants::tss::{
            TPM2_CC_DictionaryAttackParameters, TPM2_RH_LOCKOUT, TPM2_RS_PW, TPM2_ST_SESSIONS,
        };
        let mut body = Vec::new();
        body.extend_from_slice(&TPM2_RH_LOCKOUT.to_be_bytes());
        // Password session with an empty password: handle, nonce (0), attributes, hmac (0).
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&TPM2_RS_PW.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0, 0]);
        for value in [max_tries, recovery_s, lockout_recovery_s] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        let mut command = Vec::new();
        command.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        let size = u32::try_from(10 + body.len()).expect("size");
        command.extend_from_slice(&size.to_be_bytes());
        command.extend_from_slice(&TPM2_CC_DictionaryAttackParameters.to_be_bytes());
        command.extend_from_slice(&body);

        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream.write_all(&command).expect("send");
        let mut header = [0u8; 10];
        stream.read_exact(&mut header).expect("response");
        let rc = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
        assert_eq!(rc, 0, "TPM2_DictionaryAttackParameters failed: {rc:#x}");
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

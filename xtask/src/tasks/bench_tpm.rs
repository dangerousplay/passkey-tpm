use crate::runner::{cargo, exec, Result};

/// `cargo xtask bench-tpm [--device PATH]`: assertion latency against swtpm, or a real TPM.
pub fn run(args: &[String]) -> Result {
    let mut cmd = cargo();
    cmd.args([
        "test",
        "--release",
        "--locked",
        "-p",
        "passkey-tpm-tpm",
        "--test",
        "bench",
        "--",
        "--ignored",
        "--nocapture",
    ]);
    if let Some(pos) = args.iter().position(|a| a == "--device") {
        let device = args.get(pos + 1).map_or("/dev/tpmrm0", String::as_str);
        cmd.env("PASSKEY_TPM_BENCH_TCTI", format!("device:{device}"));
    }
    exec(&mut cmd)
}

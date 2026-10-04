//! `passkey-tpm info`: a diagnostics report for bug reports.
//!
//! Every probe is best effort: a failure becomes a line in the report, never an error. The
//! report contains no secrets, serial numbers, user names or credential data.

use std::path::Path;
use std::process::Command;

use passkey_tpm_tpm::{health, srk};
use tss_esapi::constants::PropertyTag;
use tss_esapi::Context;

/// `PRETTY_NAME` from an os-release file.
pub fn pretty_name(os_release: &str) -> Option<String> {
    os_release.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        Some(value.trim().trim_matches(['"', '\'']).to_owned())
    })
}

/// A TPM property holding up to four ASCII characters (manufacturer, vendor strings).
pub fn property_text(value: u32) -> String {
    value
        .to_be_bytes()
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| char::from(*b))
        .collect::<String>()
        .trim()
        .to_owned()
}

/// TPM firmware version from TPM_PT_FIRMWARE_VERSION_1/2, as four 16-bit fields.
pub fn firmware_version(v1: u32, v2: u32) -> String {
    format!("{}.{}.{}.{}", v1 >> 16, v1 & 0xffff, v2 >> 16, v2 & 0xffff)
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn unknown(value: Option<String>) -> String {
    value.unwrap_or_else(|| "unknown".to_owned())
}

fn os_line() -> String {
    let os = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .ok()
        .and_then(|text| pretty_name(&text));
    unknown(os)
}

fn machine_line() -> String {
    // product_version carries the marketing name on Lenovo; serial numbers are never read.
    let dmi = Path::new("/sys/class/dmi/id");
    let parts: Vec<String> = ["sys_vendor", "product_name", "product_version"]
        .iter()
        .filter_map(|f| read_trimmed(dmi.join(f)))
        .filter(|v| {
            !matches!(
                v.as_str(),
                "None" | "Default string" | "System Product Name"
            )
        })
        .filter(|v| !v.contains("To be filled"))
        .collect();
    if parts.is_empty() {
        "unknown".to_owned()
    } else {
        parts.join(" ")
    }
}

fn device_line(path: &str) -> String {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(_) => format!("{path} present, accessible"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            format!("{path} present, not accessible to this user")
        }
        Err(e) => format!("{path} {e}"),
    }
}

fn tpm_lines(out: &mut Vec<(String, String)>) {
    let version = read_trimmed("/sys/class/tpm/tpm0/tpm_version_major").map_or_else(
        || "no TPM found by the kernel".to_owned(),
        |v| format!("TPM {v}.0"),
    );
    out.push(("tpm".into(), version));
    out.push(("tpm device".into(), device_line("/dev/tpmrm0")));
    let mut ctx = match crate::context() {
        Ok(ctx) => ctx,
        Err(e) => {
            out.push((
                "tpm details".into(),
                format!("{e} (run with sudo for vendor and lockout details)"),
            ));
            return;
        }
    };
    out.push(("tpm vendor".into(), tpm_vendor(&mut ctx)));
    out.push((
        "tpm srk".into(),
        match srk::open(&mut ctx) {
            Ok(s) => format!("present, bus protection {:?}", s.bus),
            Err(e) => format!("{e}"),
        },
    ));
    out.push((
        "tpm dictionary-attack".into(),
        match health::da_status(&mut ctx) {
            Ok(da) => format!(
                "max tries {}, recovery {} s, failures {}, lockout {}, lockout password {}",
                da.max_tries,
                da.recovery_interval_s,
                da.failed_tries,
                da.in_lockout,
                if da.lockout_auth_set {
                    "set"
                } else {
                    "not set"
                }
            ),
            Err(e) => e.to_string(),
        },
    ));
}

fn tpm_vendor(ctx: &mut Context) -> String {
    let mut get = |tag| ctx.get_tpm_property(tag).ok().flatten();
    let manufacturer = get(PropertyTag::Manufacturer).map(property_text);
    let vendor: String = [
        PropertyTag::VendorString1,
        PropertyTag::VendorString2,
        PropertyTag::VendorString3,
        PropertyTag::VendorString4,
    ]
    .into_iter()
    .filter_map(&mut get)
    .map(property_text)
    .collect();
    let firmware = match (
        get(PropertyTag::FirmwareVersion1),
        get(PropertyTag::FirmwareVersion2),
    ) {
        (Some(v1), Some(v2)) => firmware_version(v1, v2),
        _ => "unknown".to_owned(),
    };
    let manufacturer = unknown(manufacturer);
    if vendor.is_empty() || vendor == manufacturer {
        format!("{manufacturer}, firmware {firmware}")
    } else {
        format!("{manufacturer} {vendor}, firmware {firmware}")
    }
}

fn fprintd_line() -> String {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return format!("cannot start runtime: {e}"),
    };
    runtime.block_on(async {
        let conn = match zbus::Connection::system().await {
            Ok(conn) => conn,
            Err(e) => return format!("system bus unavailable: {e}"),
        };
        let device = match passkey_tpm_uv::fprintd::device_description(&conn).await {
            Ok(device) => device,
            Err(e) => return format!("no usable device ({e})"),
        };
        let enrolled = match std::env::var("USER") {
            Ok(user) => match passkey_tpm_uv::fprintd::has_enrolled(&conn, &user).await {
                Ok(true) => "yes".to_owned(),
                Ok(false) => "no".to_owned(),
                Err(e) => format!("unknown ({e})"),
            },
            Err(_) => "unknown".to_owned(),
        };
        format!("{device}, fingers enrolled for this user: {enrolled}")
    })
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

fn unit_state(user: bool, unit: &str) -> String {
    let mut args = vec!["is-active", unit];
    if user {
        args.insert(0, "--user");
    }
    unknown(command_output("systemctl", &args))
}

fn first_line(program: &str, args: &[&str]) -> String {
    command_output(program, args)
        .and_then(|text| text.lines().next().map(str::to_owned))
        .unwrap_or_else(|| "not found".to_owned())
}

/// Collects the report as label/value pairs.
pub fn collect() -> Vec<(String, String)> {
    let mut out = vec![
        ("passkey-tpm".to_owned(), crate::version()),
        ("os".to_owned(), os_line()),
        (
            "kernel".to_owned(),
            unknown(read_trimmed("/proc/sys/kernel/osrelease")),
        ),
        ("machine".to_owned(), machine_line()),
    ];
    tpm_lines(&mut out);
    out.push(("uhid".into(), device_line("/dev/uhid")));
    out.push(("fingerprint".into(), fprintd_line()));
    // Debian/Fedora install fprintd in /usr/libexec, Arch in /usr/lib.
    let fprintd = ["/usr/libexec/fprintd", "/usr/lib/fprintd"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .map_or_else(|| "not found".to_owned(), |p| first_line(p, &["--version"]));
    out.push(("fprintd".into(), fprintd));
    out.push((
        "broker (passkey-tpm-uvd)".into(),
        unit_state(false, "passkey-tpm-uvd.service"),
    ));
    out.push((
        "agent (passkey-tpm-agent)".into(),
        unit_state(true, "passkey-tpm-agent.service"),
    ));
    out.push((
        "security keys (fido2-token -L)".into(),
        command_output("fido2-token", &["-L"])
            .unwrap_or_else(|| "none or fido2-tools not installed".to_owned()),
    ));
    out
}

/// Formats the report for pasting into an issue.
pub fn render(lines: &[(String, String)]) -> String {
    let width = lines.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    lines
        .iter()
        .map(|(k, v)| {
            format!(
                "{k:<width$}  {}\n",
                v.replace('\n', &format!("\n{:width$}  ", ""))
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pretty_name() {
        let text = "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
        assert_eq!(pretty_name(text).as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(pretty_name("ID=arch\n"), None);
    }

    #[test]
    fn decodes_tpm_text_properties() {
        assert_eq!(property_text(u32::from_be_bytes(*b"AMD\0")), "AMD");
        assert_eq!(property_text(u32::from_be_bytes(*b"IFX ")), "IFX");
        assert_eq!(property_text(u32::from_be_bytes(*b"INTC")), "INTC");
    }

    #[test]
    fn formats_firmware_version() {
        assert_eq!(firmware_version(0x0007_003F, 0x0001_0002), "7.63.1.2");
    }

    #[test]
    fn renders_aligned_multiline_values() {
        let lines = vec![
            ("os".to_owned(), "Arch".to_owned()),
            ("keys".to_owned(), "a\nb".to_owned()),
        ];
        assert_eq!(render(&lines), "os    Arch\nkeys  a\n      b\n");
    }
}

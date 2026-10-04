"""The installed system: files, users, devices and units, checked with testinfra."""

import pytest

LIBEXEC = "/usr/libexec/passkey-tpm"


@pytest.mark.parametrize(
    ("path", "mode"),
    [
        (f"{LIBEXEC}/passkey-tpm-uvd", 0o755),
        (f"{LIBEXEC}/passkey-tpm-agent", 0o755),
        ("/usr/bin/passkey-tpm-cli", 0o755),
        ("/usr/lib/systemd/system/passkey-tpm-uvd.service", 0o644),
        ("/usr/lib/systemd/user/passkey-tpm-agent.service", 0o644),
        ("/usr/share/dbus-1/system.d/io.github.dangerousplay.PasskeyTpm1.conf", 0o644),
        ("/usr/share/dbus-1/system-services/io.github.dangerousplay.PasskeyTpm1.service", 0o644),
        ("/usr/share/polkit-1/rules.d/50-passkey-tpm-fprintd.rules", 0o644),
        ("/usr/lib/udev/rules.d/70-passkey-tpm-uhid.rules", 0o644),
        ("/usr/lib/sysusers.d/passkey-tpm.conf", 0o644),
        ("/usr/lib/modules-load.d/passkey-tpm.conf", 0o644),
    ],
)
def test_packaged_file(host, path, mode):
    f = host.file(path)
    assert f.is_file, path
    assert f.mode == mode, f"{path}: {oct(f.mode)}"
    assert f.user == "root"


def test_units_point_at_installed_binaries(host):
    assert f"ExecStart={LIBEXEC}/passkey-tpm-uvd" in host.file("/usr/lib/systemd/system/passkey-tpm-uvd.service").content_string


def test_broker_system_user_is_in_tss(host):
    user = host.user("passkey-tpm")
    assert user.exists
    assert "tss" in user.groups
    assert user.shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/nologin")


def test_tpm_device_is_group_tss(host):
    dev = host.file("/dev/tpmrm0")
    assert dev.exists
    assert dev.group == "tss"
    assert dev.mode & 0o060 == 0o060


def test_uhid_loaded_by_modules_load(host):
    assert host.file("/dev/uhid").exists, "modules-load.d should load uhid at boot"


def test_broker_unit_is_hardened(host):
    out = host.run("systemd-analyze security passkey-tpm-uvd.service --no-pager")
    assert out.rc == 0, out.stderr
    # The overall exposure is the last line, e.g. "→ Overall exposure level ...: 0.6 SAFE".
    exposure = float(out.stdout.strip().splitlines()[-1].split(":")[1].split()[0])
    assert exposure <= 2.0, out.stdout.splitlines()[-1]


def test_test_users_exist(host):
    assert host.user("alice").exists and host.user("bob").exists

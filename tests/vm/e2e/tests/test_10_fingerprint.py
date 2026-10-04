"""Real fprintd with libfprint's virtual device: both users enroll a finger."""

import pkt


def test_fprintd_uses_the_virtual_driver(host):
    lib = host.run("ls /usr/lib/*/libfprint-2.so.2").stdout.split()[0]
    assert host.run(f"grep -qa FP_VIRTUAL_DEVICE {lib}").rc == 0


def test_users_are_enrolled(enrolled):
    for user in enrolled:
        out = pkt.run("fprintd-list", user).stdout
        assert "right-index-finger" in out, out


def test_info_reports_tpm_and_fingerprint(enrolled):
    """`passkey-tpm-cli info` is what bug reports ask for: it must work on a real system."""
    env = {"PATH": "/usr/bin:/bin", "USER": enrolled[0]}
    out = pkt.run("passkey-tpm-cli", "info", env=env).stdout
    assert "TPM 2.0" in out, out
    assert "tpm vendor" in out and "firmware" in out, out
    assert "fingers enrolled for this user: yes" in out, out
    assert pkt.run("passkey-tpm-cli", "version").stdout.startswith("passkey-tpm "), out

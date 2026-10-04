"""Real fprintd with libfprint's virtual device: both users enroll a finger."""

import pkt


def test_fprintd_uses_the_virtual_driver(host):
    lib = host.run("ls /usr/lib/*/libfprint-2.so.2").stdout.split()[0]
    assert host.run(f"grep -qa FP_VIRTUAL_DEVICE {lib}").rc == 0


def test_users_are_enrolled(enrolled):
    for user in enrolled:
        out = pkt.run("fprintd-list", user).stdout
        assert "right-index-finger" in out, out

"""libfido2's command-line tools against alice's virtual security key."""

import base64
import os

import pkt


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_token_info(alice):
    out = pkt.run("fido2-token", "-I", alice.hidraw).stdout
    assert "FIDO_2_1" in out
    assert "credMgmt" in out


def test_register_and_assert_with_uv(alice, tmp_path):
    rp = "libfido2.passkey-tpm.test"
    (tmp_path / "cred.in").write_text(f"{b64(os.urandom(32))}\n{rp}\nalice\n{b64(os.urandom(16))}\n")
    pkt.run("fido2-cred", "-M", "-i", str(tmp_path / "cred.in"), "-o", str(tmp_path / "cred.out"), alice.hidraw, "es256")
    pkt.run("fido2-cred", "-V", "-v", "-i", str(tmp_path / "cred.out"), "-o", str(tmp_path / "cred.pub"), "es256")
    cred_id = (tmp_path / "cred.out").read_text().splitlines()[4]
    (tmp_path / "assert.in").write_text(f"{b64(os.urandom(32))}\n{rp}\n{cred_id}\n")
    pkt.run("fido2-assert", "-G", "-i", str(tmp_path / "assert.in"), "-o", str(tmp_path / "assert.out"), alice.hidraw)
    # -v: the signed authenticator data must carry the UV flag.
    pkt.run("fido2-assert", "-V", "-v", "-i", str(tmp_path / "assert.out"), str(tmp_path / "cred.pub"), "es256")

"""Two users, two agents, one broker: credentials never cross users (TPM-05)."""

import os

import pytest
from fido2.ctap import CtapError

import pkt

RP = {"id": "isolation.passkey-tpm.test", "name": "isolation"}


def test_each_user_has_their_own_device(alice, bob):
    assert alice.hidraw != bob.hidraw


def test_bob_cannot_use_alices_credential(alice, bob):
    att = alice.ctap().make_credential(
        os.urandom(32), RP, {"id": b"alice", "name": "alice"}, [{"type": "public-key", "alg": -7}]
    )
    cred = {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
    # Sanity: alice can use it.
    alice.ctap().get_assertion(RP["id"], os.urandom(32), allow_list=[cred])
    before = pkt.broker_requests_from(bob.uid)
    with pytest.raises(CtapError) as e:
        bob.ctap().get_assertion(RP["id"], os.urandom(32), allow_list=[cred])
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS
    assert pkt.broker_requests_from(bob.uid) > before, "the broker saw the request as bob's"


def test_users_get_separate_gates(alice, bob):
    out = pkt.run("passkey-tpm", "tpm", "status").stdout
    indexes = [l for l in out.splitlines() if l.strip().startswith("0x015")]
    assert len(indexes) >= 6, f"3 gates per user expected:\n{out}"

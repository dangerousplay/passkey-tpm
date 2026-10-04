"""Two users, two agents, one broker: credentials never cross users (TPM-05), and only the
user in front of the seat can reach the authenticator (HARD-01)."""

import os

import pytest
from fido2.ctap import CtapError

import pkt

RP = {"id": "isolation.passkey-tpm.test", "name": "isolation"}
GET_INFO = bytes([0x04])
OPERATION_DENIED = bytes([0x27])


def test_only_the_seat_user_has_a_device(alice, bob):
    pkt.activate("alice")
    pkt.wait_for(lambda: not pkt.hidraw_nodes(bob.uid), what="bob's device to go away")
    assert len(pkt.hidraw_nodes(alice.uid)) == 1
    pkt.activate("bob")
    pkt.wait_for(lambda: not pkt.hidraw_nodes(alice.uid), what="alice's device to go away")
    assert len(pkt.hidraw_nodes(bob.uid)) == 1


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


def test_broker_refuses_a_user_in_the_background(alice, bob):
    pkt.activate("alice")
    assert pkt.busctl_ctap("alice", GET_INFO)[0] == 0x00
    pkt.activate("bob")
    assert pkt.busctl_ctap("alice", GET_INFO) == OPERATION_DENIED
    assert pkt.busctl_ctap("bob", GET_INFO)[0] == 0x00


def test_descriptor_opened_before_a_switch_stops_working(alice, bob):
    """Fast user switching: whoever holds alice's hidraw node when bob takes the seat must
    not keep a working handle to alice's authenticator."""
    node = alice.hidraw
    held = os.open(node, os.O_RDWR)
    try:
        pkt.activate("bob")
        pkt.wait_for(lambda: not os.path.exists(node), what="alice's node to be removed")
        with pytest.raises(OSError):
            os.write(held, bytes(65))
    finally:
        os.close(held)
    before = pkt.broker_requests_from(alice.uid)
    pkt.activate("alice")
    assert pkt.broker_requests_from(alice.uid) == before, "nothing reached the broker as alice"


def nv_indexes() -> list[str]:
    out = pkt.run("passkey-tpm", "tpm", "status").stdout
    return [l.strip() for l in out.splitlines() if l.strip().startswith("0x015")]


def test_users_get_separate_gates(alice, bob):
    # Read-only requests provision nothing (HARD-09); bob's gates appear on his first
    # credential.
    before = nv_indexes()
    pkt.activate("bob")
    assert pkt.busctl_ctap("bob", GET_INFO)[0] == 0x00
    assert nv_indexes() == before, "getInfo must not define NV indexes"
    bob.ctap().make_credential(
        os.urandom(32), RP, {"id": b"bob", "name": "bob"}, [{"type": "public-key", "alg": -7}]
    )
    after = nv_indexes()
    assert len(after) >= 6, f"3 gates per user expected: {after}"
    assert len(after) == len(before) + 3 or len(before) >= 6

"""CTAP 2.1 against alice's key: PIN, tokens, discoverable credentials, hmac-secret,
credential management, selection and reset. Tests run in order on shared state."""

import hashlib
import os
from types import SimpleNamespace

import pytest
from fido2.attestation import PackedAttestation
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2

RP = {"id": "e2e.passkey-tpm.test", "name": "passkey-tpm E2E"}
PIN = "246810"
NEW_PIN = "13579864"
ES256 = [{"type": "public-key", "alg": -7}]
P = ClientPin.PERMISSION


@pytest.fixture(scope="module")
def s(alice):
    ctap = alice.ctap()
    protocol = PinProtocolV2()
    return SimpleNamespace(ctap=ctap, protocol=protocol, cp=ClientPin(ctap, protocol), cred=None, pub=None, user=None)


def hmac_input(cp, protocol, salts):
    key_agreement, shared = cp._get_shared_secret()
    salt_enc = protocol.encrypt(shared, salts)
    return shared, {1: key_agreement, 2: salt_enc, 3: protocol.authenticate(shared, salt_enc), 4: protocol.VERSION}


def test_get_info(s):
    info = s.ctap.get_info()
    assert "FIDO_2_1" in info.versions
    assert info.options["rk"] and info.options["credMgmt"]
    assert {"hmac-secret", "credProtect"} <= set(info.extensions)
    assert info.options["clientPin"] is False, "fresh user"


def test_set_pin(s):
    s.cp.set_pin(PIN)
    assert s.ctap.get_info().options["clientPin"] is True
    assert s.cp.get_pin_retries()[0] == 8


def test_make_discoverable_credential_with_pin_token(s):
    token = s.cp.get_pin_token(PIN, P.MAKE_CREDENTIAL | P.GET_ASSERTION, RP["id"])
    s.user = {"id": os.urandom(16), "name": "alice", "displayName": "Alice"}
    cdh = os.urandom(32)
    att = s.ctap.make_credential(
        cdh, RP, s.user, ES256,
        extensions={"hmac-secret": True, "credProtect": 2},
        options={"rk": True},
        pin_uv_param=s.protocol.authenticate(token, cdh),
        pin_uv_protocol=s.protocol.VERSION,
    )
    assert att.fmt == "packed"
    PackedAttestation().verify(att.att_stmt, att.auth_data, cdh)
    assert att.auth_data.is_user_verified() and att.auth_data.is_user_present()
    assert att.auth_data.extensions == {"hmac-secret": True, "credProtect": 3}
    s.cred = att.auth_data.credential_data
    s.pub = CoseKey.parse(s.cred.public_key)


def test_discoverable_assertion_and_deterministic_hmac_secret(s):
    salts = os.urandom(32)
    outputs = []
    for _ in range(2):
        shared, ext = hmac_input(s.cp, s.protocol, salts)
        cdh = os.urandom(32)
        a = s.ctap.get_assertion(RP["id"], cdh, extensions={"hmac-secret": ext})
        s.pub.verify(a.auth_data + cdh, a.signature)
        assert a.credential["id"] == s.cred.credential_id
        assert a.user["id"] == s.user["id"]
        outputs.append(s.protocol.decrypt(shared, a.auth_data.extensions["hmac-secret"]))
    assert outputs[0] == outputs[1] and len(outputs[0]) == 32


def test_hmac_secret_protocol_one_two_salts(s):
    p1 = PinProtocolV1()
    shared, ext = hmac_input(ClientPin(s.ctap, p1), p1, os.urandom(64))
    a = s.ctap.get_assertion(RP["id"], os.urandom(32), extensions={"hmac-secret": ext})
    assert len(p1.decrypt(shared, a.auth_data.extensions["hmac-secret"])) == 64


def test_uv_token_needs_no_second_touch(s):
    token = s.cp.get_uv_token(P.GET_ASSERTION, RP["id"])
    cdh = os.urandom(32)
    a = s.ctap.get_assertion(
        RP["id"], cdh,
        allow_list=[{"type": "public-key", "id": s.cred.credential_id}],
        pin_uv_param=s.protocol.authenticate(token, cdh),
        pin_uv_protocol=s.protocol.VERSION,
    )
    s.pub.verify(a.auth_data + cdh, a.signature)
    assert a.auth_data.is_user_verified()


def test_wrong_finger_is_denied(s, wrong_finger):
    with pytest.raises(CtapError) as e:
        s.ctap.get_assertion(RP["id"], os.urandom(32))
    assert e.value.code == CtapError.ERR.OPERATION_DENIED


def test_credential_management(s):
    cm = CredentialManagement(s.ctap, s.protocol, s.cp.get_pin_token(PIN, P.CREDENTIAL_MGMT))
    assert cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
    assert cm.enumerate_rps()[0][CredentialManagement.RESULT.RP]["id"] == RP["id"]
    creds = cm.enumerate_creds(hashlib.sha256(RP["id"].encode()).digest())
    assert creds[0][CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == s.cred.credential_id
    descriptor = {"type": "public-key", "id": s.cred.credential_id}
    cm.update_user_info(descriptor, {"id": s.user["id"], "name": "alice2", "displayName": "Alice 2"})
    assert s.ctap.get_assertion(RP["id"], os.urandom(32)).user["name"] == "alice2"
    cm.delete_cred(descriptor)
    with pytest.raises(CtapError) as e:
        s.ctap.get_assertion(RP["id"], os.urandom(32), allow_list=[descriptor])
    assert e.value.code == CtapError.ERR.NO_CREDENTIALS, "deleted ID is revoked, even via allowList"


@pytest.mark.destructive
def test_wrong_pin_decrements_retries(s):
    with pytest.raises(CtapError) as e:
        s.cp.get_pin_token("000000", P.GET_ASSERTION, RP["id"])
    assert e.value.code == CtapError.ERR.PIN_INVALID
    assert s.cp.get_pin_retries()[0] == 7


def test_change_pin_restores_retries(s):
    s.cp.change_pin(PIN, NEW_PIN)
    assert s.cp.get_pin_retries()[0] == 8
    s.cp.get_pin_token(NEW_PIN, P.GET_ASSERTION, RP["id"])


def test_selection(s):
    s.ctap.selection()


def test_reset_clears_the_users_state(s):
    s.ctap.reset()
    assert s.ctap.get_info().options["clientPin"] is False

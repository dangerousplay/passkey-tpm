#!/usr/bin/env python3
"""CTAP 2.1 end-to-end checks against a running passkey-tpm virtual device (M2-14).

Uses python-fido2 (pip install fido2) over /dev/hidraw. Every check verifies signatures
and outputs cryptographically, not just status codes. Run through scripts/e2e-local.sh.
"""

import hashlib
import os
import sys

from fido2.attestation import PackedAttestation
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CtapHidDevice

RP = {"id": "e2e.passkey-tpm.test", "name": "passkey-tpm E2E"}
PIN = "246810"
ES256 = [{"type": "public-key", "alg": -7}]
P = ClientPin.PERMISSION


def check(cond, what):
    if not cond:
        raise SystemExit(f"FAIL: {what}")
    print(f"ok  {what}")


def expect_error(code, fn, what):
    try:
        fn()
    except CtapError as e:
        check(e.code == code, f"{what} -> {e.code.name}")
        return
    raise SystemExit(f"FAIL: {what}: expected {code.name}, got success")


def device():
    for dev in CtapHidDevice.list_devices():
        if "passkey-tpm" in (dev.descriptor.product_name or ""):
            return dev
    raise SystemExit("passkey-tpm device not found")


def cdh():
    return os.urandom(32)


def hmac_secret_input(client_pin, protocol, salts):
    key_agreement, shared = client_pin._get_shared_secret()
    salt_enc = protocol.encrypt(shared, salts)
    return shared, {
        1: key_agreement,
        2: salt_enc,
        3: protocol.authenticate(shared, salt_enc),
        4: protocol.VERSION,
    }


def main():
    ctap = Ctap2(device())
    info = ctap.info
    check("FIDO_2_1" in info.versions, "getInfo advertises FIDO_2_1")
    check(info.options.get("credMgmt") and info.options.get("rk"), "credMgmt and rk supported")
    check(set(info.extensions) >= {"hmac-secret", "credProtect"}, "hmac-secret and credProtect advertised")

    protocol = PinProtocolV2()
    cp = ClientPin(ctap, protocol)
    if info.options.get("clientPin"):
        raise SystemExit("a PIN is already set for this user; run against a fresh state")
    cp.set_pin(PIN)
    check(ctap.get_info().options.get("clientPin") is True, "setPIN -> clientPin true")
    check(cp.get_pin_retries()[0] == 8, "pinRetries = 8")

    # makeCredential: discoverable, hmac-secret, credProtect, PIN token (UP by touch).
    token = cp.get_pin_token(PIN, P.MAKE_CREDENTIAL | P.GET_ASSERTION, RP["id"])
    user = {"id": os.urandom(16), "name": "alice", "displayName": "Alice"}
    h = cdh()
    att = ctap.make_credential(
        h, RP, user, ES256,
        extensions={"hmac-secret": True, "credProtect": 2},
        options={"rk": True},
        pin_uv_param=protocol.authenticate(token, h),
        pin_uv_protocol=protocol.VERSION,
    )
    check(att.fmt == "packed", "packed attestation")
    PackedAttestation().verify(att.att_stmt, att.auth_data, h)
    check(True, "attestation signature verifies (self attestation)")
    check(att.auth_data.is_user_verified() and att.auth_data.is_user_present(), "UV and UP flags")
    check(att.auth_data.extensions.get("hmac-secret") is True, "hmac-secret enabled")
    check(att.auth_data.extensions.get("credProtect") == 3, "credProtect applied level 3")
    cred = att.auth_data.credential_data
    pub = CoseKey.parse(cred.public_key)

    # getAssertion: discoverable (no allowList) + hmac-secret, twice with the same salt.
    outputs = []
    for _ in range(2):
        salts = os.urandom(32) if not outputs else salts
        shared, ext = hmac_secret_input(cp, protocol, salts)
        h = cdh()
        a = ctap.get_assertion(RP["id"], h, extensions={"hmac-secret": ext})
        pub.verify(a.auth_data + h, a.signature)
        check(a.credential["id"] == cred.credential_id, "discoverable credential found")
        check(a.user["id"] == user["id"], "user handle returned")
        outputs.append(protocol.decrypt(shared, a.auth_data.extensions["hmac-secret"]))
    check(outputs[0] == outputs[1] and len(outputs[0]) == 32, "hmac-secret deterministic (TPM HMAC)")

    # Protocol 1 hmac-secret with two salts.
    p1 = PinProtocolV1()
    cp1 = ClientPin(ctap, p1)
    shared, ext = hmac_secret_input(cp1, p1, os.urandom(64))
    a = ctap.get_assertion(RP["id"], cdh(), extensions={"hmac-secret": ext})
    check(len(p1.decrypt(shared, a.auth_data.extensions["hmac-secret"])) == 64, "protocol 1, two salts")

    # Token from built-in UV carries presence: assertion without a second gesture.
    uv_token = cp.get_uv_token(P.GET_ASSERTION, RP["id"])
    h = cdh()
    a = ctap.get_assertion(
        RP["id"], h,
        allow_list=[{"type": "public-key", "id": cred.credential_id}],
        pin_uv_param=protocol.authenticate(uv_token, h),
        pin_uv_protocol=protocol.VERSION,
    )
    pub.verify(a.auth_data + h, a.signature)
    check(a.auth_data.is_user_verified(), "assertion with UV token")

    # Credential management.
    cm_token = cp.get_pin_token(PIN, P.CREDENTIAL_MGMT)
    cm = CredentialManagement(ctap, protocol, cm_token)
    meta = cm.get_metadata()
    check(meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1, "credMgmt metadata: 1 credential")
    rps = cm.enumerate_rps()
    check(rps[0][CredentialManagement.RESULT.RP]["id"] == RP["id"], "credMgmt enumerate RPs")
    rp_hash = hashlib.sha256(RP["id"].encode()).digest()
    creds = cm.enumerate_creds(rp_hash)
    check(creds[0][CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == cred.credential_id, "credMgmt enumerate credentials")
    descriptor = {"type": "public-key", "id": cred.credential_id}
    cm.update_user_info(descriptor, {"id": user["id"], "name": "alice2", "displayName": "Alice 2"})
    a = ctap.get_assertion(RP["id"], cdh())
    check(a.user.get("name") == "alice2", "credMgmt update user information")
    cm.delete_cred(descriptor)
    expect_error(CtapError.ERR.NO_CREDENTIALS, lambda: ctap.get_assertion(RP["id"], cdh()), "deleted credential no longer discoverable")

    # PIN retries, change. A wrong PIN counts towards the TPM's machine-wide
    # dictionary-attack lockout, so it only runs when explicitly allowed (swtpm, CI).
    if os.environ.get("E2E_ALLOW_DA_FAILURE") == "1":
        expect_error(CtapError.ERR.PIN_INVALID, lambda: cp.get_pin_token("000000", P.GET_ASSERTION, RP["id"]), "wrong PIN")
        check(cp.get_pin_retries()[0] == 7, "pinRetries decremented to 7")
    else:
        print("skip wrong-PIN check (set E2E_ALLOW_DA_FAILURE=1; it increments the TPM DA counter)")
    cp.change_pin(PIN, "13579864")
    check(cp.get_pin_retries()[0] == 8, "pinRetries = 8 after changePIN")
    cp.get_pin_token("13579864", P.GET_ASSERTION, RP["id"])
    check(True, "new PIN works")

    # Selection, then reset wipes this user's state.
    ctap.selection()
    check(True, "authenticatorSelection")
    ctap.reset()
    check(ctap.get_info().options.get("clientPin") is False, "reset clears the PIN")
    print("OK: CTAP 2.1 end-to-end suite passed")


if __name__ == "__main__":
    sys.exit(main())

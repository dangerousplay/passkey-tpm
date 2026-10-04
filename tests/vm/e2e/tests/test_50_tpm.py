"""TPM-level facts on the VM's swtpm (a discrete-like TPM)."""

import pkt


def test_swtpm_uses_encrypted_sessions():
    out = pkt.run("passkey-tpm", "tpm", "status").stdout
    assert "bus protection Encrypted" in out, out


def test_cli_warns_about_weak_dictionary_attack_policy():
    # swtpm's defaults: no lockout password and fewer tries than CTAP's 8 PIN retries.
    out = pkt.run("passkey-tpm", "tpm", "status").stdout
    assert "no lockout password" in out
    assert "must exceed the CTAP PIN retry limit" in out

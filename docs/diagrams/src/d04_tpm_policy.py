"""D04: TPM policy model (ADR 0003 with amendment 1)."""
from spinagram import Diagram

d = Diagram(
    "D04",
    "TPM policy model",
    subtitle="Every signature needs the UV gate secret, which only the broker holds",
    layout={"engine": "dot", "direction": "right"},
    source="docs/adr/0003-tpm-policy-model.md (amendment 1)",
    category="security",
)

with d.group("Proof from the user", direction="down"):
    finger = d.box("Fingerprint match", text="fprintd, calling user", icon="network:fingerprint")
    pin = d.box("PIN", text="via a pinUvAuthToken", icon="network:padlock-plain")

broker = d.box("Broker", text="sole gate holder", style="dark", icon="selfhosted:rust")

with d.group("TPM 2.0", direction="down"):
    pin_gate = d.box("PIN gate", text="NV index, DA-limited", style="warning")
    uv_gate = d.box("UV gate", text="NV index, noDA, random secret")
    key = d.box("Credential key", text="PolicySecret(UV, H(tag‖rpIdHash))", style="dark",
                icon="terrastruct:tech-cpu")

sig = d.box("Signature", text="UP+UV flags, counter 0", style="neutral")

finger.to(broker, "match")
pin.to(broker, "token")
broker.to(pin_gate, "check PIN")
broker.to(uv_gate, "PolicySecret")
uv_gate.to(key, "unlocks")
key >> sig

diagram = d

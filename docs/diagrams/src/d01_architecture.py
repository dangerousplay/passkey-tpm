"""D01: components and trust boundaries of passkey-tpm."""
from spinagram import Diagram

d = Diagram(
    "D01",
    "passkey-tpm architecture",
    subtitle="Only the broker can use passkey keys: the session side relays CTAP and shows prompts",
    layout={"engine": "dot", "direction": "right"},
    category="architecture",
)

with d.group("Your session (untrusted)", direction="down"):
    apps = d.box("Browser, FIDO2 tools", text="Firefox, Chromium, pam_u2f", icon="selfhosted:firefox")
    agent = d.box("passkey-tpm-agent", text="virtual key + prompts", icon="selfhosted:rust")
    tray = d.box("passkey-tpm-tray", text="status, enroll, PIN", icon="network:fingerprint-circle")

hid = d.box("Kernel HID", text="hidraw ⇄ uhid", icon="selfhosted:arch-linux")

with d.group("System", direction="down"):
    broker = d.box("passkey-tpm-uvd", text="broker, verified core", style="dark", icon="network:padlock-plain")
    fprintd = d.box("fprintd", text="fingerprint match", icon="network:fingerprint")
    logind = d.box("logind", text="user at the seat", icon="network:server")

tpm = d.box("TPM 2.0", text="keys behind PIN/UV gates", style="dark", icon="terrastruct:tech-cpu")

apps.to(hid, "CTAPHID")
hid.to(agent, "uhid")
agent.to(broker, "Ctap")
tray.to(broker, "PIN")
tray.to(fprintd, "enroll")
broker.to(fprintd, "verify")
broker.to(logind, "seat")
broker.to(tpm, "sign")

diagram = d

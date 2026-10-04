"""Helpers for the passkey-tpm VM scenarios: virtual fingerprint, agents, devices."""

from __future__ import annotations

import glob
import json
import os
import pwd
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice

LIBEXEC = Path("/usr/libexec/passkey-tpm")
FP_SOCKET = "/run/fprintd-virtual.sock"
FINGER = "e2e-finger"


def run(*cmd: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True, **kw)


class VirtualFinger:
    """Drives libfprint's virtual device: a background thread keeps "touching" with
    `current` (the enrolled finger by default; tests may switch to a wrong one)."""

    def __init__(self) -> None:
        self.current = FINGER
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _send(self, command: str) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(FP_SOCKET)
            s.sendall(command.encode())

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._send(f"SCAN {self.current}")
            except OSError:
                pass  # fprintd not started yet, or between claims
            time.sleep(0.4)

    def start(self) -> "VirtualFinger":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def hidraw_nodes(uid: int | None = None) -> set[str]:
    """passkey-tpm hidraw nodes; with `uid`, only that user's agent's (HID_PHYS carries it)."""
    nodes = set()
    for uevent in glob.glob("/sys/class/hidraw/hidraw*/device/uevent"):
        text = Path(uevent).read_text()
        if "HID_NAME=passkey-tpm" not in text:
            continue
        if uid is not None and f"HID_PHYS=passkey-tpm-agent/uid={uid}" not in text.splitlines():
            continue
        nodes.add("/dev/" + Path(uevent).parent.parent.name)
    return nodes


def wait_for(cond, timeout: float = 10, what: str = "condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = cond()
        if value:
            return value
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {what}")


# Seat sessions (HARD-01): the broker serves, and the agent exposes a device for, only the
# user in front of seat0. Each test user gets an autologin getty on its own VT; `activate`
# switches VTs like a fast user switch.
VT = {"alice": 2, "bob": 3}


def login(user: str) -> None:
    """Starts an autologin session for `user` on its VT (seat0)."""
    vt = VT[user]
    dropin = Path(f"/run/systemd/system/getty@tty{vt}.service.d")
    dropin.mkdir(parents=True, exist_ok=True)
    (dropin / "autologin.conf").write_text(
        "[Service]\nExecStart=\n"
        f"ExecStart=-/sbin/agetty --autologin {user} --noclear %I $TERM\n"
    )
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", f"getty@tty{vt}.service")
    wait_for(lambda: seat_session(user), what=f"{user}'s seat session")


def seat_session(user: str) -> str | None:
    out = run("loginctl", "list-sessions", "--no-legend", check=False).stdout
    for line in out.splitlines():
        fields = line.split()
        # SESSION UID USER SEAT LEADER CLASS TTY ...
        if len(fields) >= 4 and fields[2] == user and fields[3] == "seat0":
            return fields[0]
    return None


def is_active(user: str) -> bool:
    session = seat_session(user)
    if session is None:
        return False
    out = run("loginctl", "show-session", session, "-p", "Active", "--value", check=False)
    return out.stdout.strip() == "yes"


def activate(user: str) -> None:
    """Brings `user`'s VT to the foreground (no-op if it already is)."""
    if not is_active(user):
        run("chvt", str(VT[user]))
        wait_for(lambda: is_active(user), what=f"{user} active on seat0")


def busctl_ctap(user: str, request: bytes) -> bytes:
    """Calls the broker directly as `user` (bypassing any agent)."""
    out = run(
        "runuser", "-u", user, "--", "busctl", "--system", "--json=short", "call",
        "io.github.dangerousplay.PasskeyTpm1", "/io/github/dangerousplay/PasskeyTpm1",
        "io.github.dangerousplay.PasskeyTpm1", "Ctap", "ay",
        str(len(request)), *(str(b) for b in request),
    ).stdout
    return bytes(json.loads(out)["data"][0])


@dataclass
class Agent:
    """A passkey-tpm-agent running as `user`. Its device exists only while `user` is active on
    seat0, and gets a new hidraw node each time it comes back."""

    user: str
    process: subprocess.Popen
    log: Path
    uid: int = field(init=False)

    def __post_init__(self) -> None:
        self.uid = pwd.getpwnam(self.user).pw_uid

    @classmethod
    def start(cls, user: str, log_dir: Path) -> "Agent":
        run("setfacl", "-m", f"u:{user}:rw", "/dev/uhid")
        log = log_dir / f"agent-{user}.log"
        process = subprocess.Popen(
            [str(LIBEXEC / "passkey-tpm-agent")],
            user=user,
            group=user,
            extra_groups=[],
            env={"PATH": "/usr/bin:/bin"},
            stdout=log.open("w"),
            stderr=subprocess.STDOUT,
        )
        agent = cls(user, process, log)
        try:
            agent.hidraw  # activates the user and waits for the device
        except TimeoutError:
            process.kill()
            raise RuntimeError(f"agent for {user} created no device; log:\n{log.read_text()}")
        return agent

    @property
    def hidraw(self) -> str:
        """This agent's device node, after bringing its user to the foreground."""
        activate(self.user)

        def node():
            if self.process.poll() is not None:
                raise RuntimeError(f"agent for {self.user} exited:\n{self.log.read_text()}")
            nodes = {n for n in hidraw_nodes(self.uid) if os.path.exists(n)}
            return nodes.pop() if len(nodes) == 1 else None

        return wait_for(node, what=f"{self.user}'s device")

    def ctap(self) -> Ctap2:
        """A CTAP2 session on this agent's device only (its user is made active first)."""
        path = self.hidraw
        for dev in CtapHidDevice.list_devices():
            if dev.descriptor.path == path:
                return Ctap2(dev)
        raise RuntimeError(f"{path} not found by python-fido2")

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()


def enroll(user: str) -> None:
    """Enrolls the virtual finger for `user` (the VirtualFinger thread provides the scans)."""
    run("fprintd-delete", user, check=False)
    run("timeout", "120", "fprintd-enroll", "-f", "right-index-finger", user)


def broker_requests_from(uid: int) -> int:
    """Number of requests the broker logged for `uid` (its audit line in the journal)."""
    out = run("journalctl", "-b", "--no-pager", "-o", "cat", check=False).stdout
    return sum(1 for line in out.splitlines() if f"request uid={uid} " in line)

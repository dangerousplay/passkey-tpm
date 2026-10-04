"""Helpers for the passkey-tpm VM scenarios: virtual fingerprint, agents, devices."""

from __future__ import annotations

import glob
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


def hidraw_nodes() -> set[str]:
    nodes = set()
    for uevent in glob.glob("/sys/class/hidraw/hidraw*/device/uevent"):
        if "HID_NAME=passkey-tpm" in Path(uevent).read_text():
            nodes.add("/dev/" + Path(uevent).parent.parent.name)
    return nodes


@dataclass
class Agent:
    """A passkey-tpm-agent running as `user`, and the hidraw node of its virtual key."""

    user: str
    process: subprocess.Popen
    hidraw: str
    log: Path
    uid: int = field(init=False)

    def __post_init__(self) -> None:
        self.uid = pwd.getpwnam(self.user).pw_uid

    @classmethod
    def start(cls, user: str, log_dir: Path) -> "Agent":
        run("setfacl", "-m", f"u:{user}:rw", "/dev/uhid")
        before = hidraw_nodes()
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
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            new = {n for n in hidraw_nodes() - before if os.path.exists(n)}
            if new:
                return cls(user, process, new.pop(), log)
            if process.poll() is not None:
                break
            time.sleep(0.1)
        process.kill()
        raise RuntimeError(f"agent for {user} created no device; log:\n{log.read_text()}")

    def ctap(self) -> Ctap2:
        """A CTAP2 session on this agent's device only."""
        for dev in CtapHidDevice.list_devices():
            if dev.descriptor.path == self.hidraw:
                return Ctap2(dev)
        raise RuntimeError(f"{self.hidraw} not found by python-fido2")

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

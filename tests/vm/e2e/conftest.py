"""Session fixtures: report directory, virtual finger, enrolled users, seat sessions, one agent
per user."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import pkt

REPORT_DIR = Path(os.environ.get("E2E_REPORT_DIR", "/tmp/passkey-tpm-report"))


@pytest.fixture(scope="session")
def report_dir() -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return REPORT_DIR


@pytest.fixture(scope="session")
def finger():
    f = pkt.VirtualFinger().start()
    yield f
    f.stop()


@pytest.fixture(scope="session")
def enrolled(finger) -> list[str]:
    users = ["alice", "bob"]
    for user in users:
        pkt.enroll(user)
    return users


@pytest.fixture(scope="session")
def seats(enrolled) -> list[str]:
    """alice and bob logged in on seat0 (VT 2 and 3); alice in the foreground."""
    for user in enrolled:
        pkt.login(user)
    pkt.activate("alice")
    return enrolled


@pytest.fixture(scope="session")
def alice(seats, report_dir):
    agent = pkt.Agent.start("alice", report_dir)
    yield agent
    agent.stop()


@pytest.fixture(scope="session")
def bob(seats, report_dir):
    agent = pkt.Agent.start("bob", report_dir)
    pkt.activate("alice")  # starting bob's agent brought bob to the front
    yield agent
    agent.stop()


@pytest.fixture(autouse=True)
def alice_in_front_afterwards(request):
    """Tests may switch users; later tests expect alice in the foreground."""
    yield
    if "seats" in request.fixturenames:
        pkt.activate("alice")


@pytest.fixture
def wrong_finger(finger):
    """Temporarily touch with a finger nobody enrolled."""
    finger.current = "not-enrolled"
    yield
    finger.current = pkt.FINGER

"""Session fixtures: report directory, virtual finger, enrolled users, one agent per user."""

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
def alice(enrolled, report_dir):
    agent = pkt.Agent.start("alice", report_dir)
    yield agent
    agent.stop()


@pytest.fixture(scope="session")
def bob(enrolled, report_dir):
    agent = pkt.Agent.start("bob", report_dir)
    yield agent
    agent.stop()


@pytest.fixture
def wrong_finger(finger):
    """Temporarily touch with a finger nobody enrolled."""
    finger.current = "not-enrolled"
    yield
    finger.current = pkt.FINGER

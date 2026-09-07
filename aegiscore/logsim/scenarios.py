"""Deterministic attack scenario definitions for AegisCore."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List

SEED = 9102
BASE_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0)
SUSPICIOUS_IPS = ("203.0.113.10", "203.0.113.11")
MALICIOUS_PARENT_PID = 1337
MALICIOUS_PID = 4242
RESPAWN_PID = 4343


@dataclass(frozen=True)
class ScenarioEvent:
    """Structured event used by the log generator."""

    timestamp: str
    channel: str
    event_type: str
    payload: Dict[str, str | int]


def build_ssh_bruteforce_with_persistence() -> List[ScenarioEvent]:
    """Return deterministic events for SSH brute force + hidden shell persistence.

    This sequence always includes exactly 50 SSH attempts inside 10 seconds,
    then a hidden shell process kill failure followed by deterministic respawn.

    TODO: Add more diverse attack families while preserving deterministic mode.
    """

    events: List[ScenarioEvent] = []
    for i in range(50):
        ts = BASE_TIMESTAMP + timedelta(milliseconds=i * 200)
        ip = SUSPICIOUS_IPS[i % len(SUSPICIOUS_IPS)]
        events.append(
            ScenarioEvent(
                timestamp=ts.isoformat(),
                channel="auth",
                event_type="ssh_failed",
                payload={"source_ip": ip, "username": "root"},
            )
        )

    process_start = BASE_TIMESTAMP + timedelta(seconds=11)
    events.append(
        ScenarioEvent(
            timestamp=process_start.isoformat(),
            channel="auth",
            event_type="process_spawn",
            payload={"pid": MALICIOUS_PID, "ppid": MALICIOUS_PARENT_PID, "name": "hidden_shell"},
        )
    )
    events.append(
        ScenarioEvent(
            timestamp=(process_start + timedelta(seconds=1)).isoformat(),
            channel="auth",
            event_type="kill_denied",
            payload={"pid": MALICIOUS_PID, "reason": "permission_denied"},
        )
    )
    events.append(
        ScenarioEvent(
            timestamp=(process_start + timedelta(seconds=2)).isoformat(),
            channel="auth",
            event_type="process_respawned",
            payload={"old_pid": MALICIOUS_PID, "pid": RESPAWN_PID, "ppid": MALICIOUS_PARENT_PID},
        )
    )
    events.append(
        ScenarioEvent(
            timestamp=(process_start + timedelta(seconds=3)).isoformat(),
            channel="access",
            event_type="suspicious_access",
            payload={"source_ip": SUSPICIOUS_IPS[0], "path": "/admin/.env"},
        )
    )
    return events

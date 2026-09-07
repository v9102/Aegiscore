"""Observer for parsing simulated auth/access logs into structured events."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


@dataclass(frozen=True)
class Event:
    """Normalized event emitted by observer parsers."""

    timestamp: str
    source_ip: Optional[str]
    event_type: str
    pid: Optional[int]
    raw_line: str


_AUTH_IP_RE = re.compile(r"^(?P<ts>\S+) sshd Failed password .* from (?P<ip>\S+) ")
_PROCESS_RE = re.compile(r"^(?P<ts>\S+) process .* pid=(?P<pid>\d+)")
_ACCESS_RE = re.compile(r"^(?P<ts>\S+) (?P<ip>\S+) GET (?P<path>\S+) ")


def parse_auth_line(line: str) -> Optional[Event]:
    """Parse one auth.log line into an Event."""

    line = line.strip()
    match = _AUTH_IP_RE.match(line)
    if match:
        return Event(match.group("ts"), match.group("ip"), "ssh_failed", None, line)

    proc_match = _PROCESS_RE.match(line)
    if proc_match:
        return Event(proc_match.group("ts"), None, "process_event", int(proc_match.group("pid")), line)

    if "kill pid=" in line:
        ts = line.split(" ", 1)[0]
        pid_match = re.search(r"pid=(\d+)", line)
        return Event(ts, None, "kill_event", int(pid_match.group(1)) if pid_match else None, line)
    return None


def parse_access_line(line: str) -> Optional[Event]:
    """Parse one access.log line into an Event."""

    line = line.strip()
    match = _ACCESS_RE.match(line)
    if match:
        return Event(match.group("ts"), match.group("ip"), "http_access", None, line)
    return None


def read_simulation_events(simulation_dir: str | Path) -> list[Event]:
    """Read full current simulation logs into event list."""

    sim_dir = Path(simulation_dir)
    events: list[Event] = []
    for path, parser in ((sim_dir / "auth.log", parse_auth_line), (sim_dir / "access.log", parse_access_line)):
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                parsed = parser(line)
                if parsed is not None:
                    events.append(parsed)
    return events


def tail_simulation_logs(simulation_dir: str | Path, poll_seconds: float = 0.25, max_polls: int = 4) -> Iterator[Event]:
    """Simple polling tail loop for scaffold/demo usage."""

    sim_dir = Path(simulation_dir)
    offsets = {"auth.log": 0, "access.log": 0}

    for _ in range(max_polls):
        for name, parser in (("auth.log", parse_auth_line), ("access.log", parse_access_line)):
            path = sim_dir / name
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8") as handle:
                handle.seek(offsets[name])
                for line in handle:
                    evt = parser(line)
                    if evt:
                        yield evt
                offsets[name] = handle.tell()
        time.sleep(poll_seconds)

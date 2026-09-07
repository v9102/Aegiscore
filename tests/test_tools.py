import json
from pathlib import Path

import pytest

from aegiscore.agent.tools import SandboxTools, run_allowlisted_command


def _state(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "blocked_ips": [],
                "kill_attempts": {},
                "known_bad_ips": ["203.0.113.10"],
                "processes": [
                    {"pid": 1337, "ppid": 1, "name": "watcher", "active": True},
                    {"pid": 4242, "ppid": 1337, "name": "hidden_shell", "active": True},
                    {"pid": 4343, "ppid": 1337, "name": "hidden_shell", "active": False},
                ],
            }
        ),
        encoding="utf-8",
    )


def test_allowlist_rejects_non_allowlisted_command() -> None:
    with pytest.raises(ValueError):
        run_allowlisted_command(["ls", "-la"])


def test_kill_process_first_attempt_fails(tmp_path: Path) -> None:
    _state(tmp_path / "sim_state.json")
    tools = SandboxTools(tmp_path)
    result = tools.kill_process(4242)
    assert not result.ok
    assert "permission denied" in result.message

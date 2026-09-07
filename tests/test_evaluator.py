import json
from pathlib import Path

from aegiscore.evaluator.evaluator import MitigationEvaluator


def test_evaluator_detects_respawn_false_success(tmp_path: Path) -> None:
    state = {
        "blocked_ips": [],
        "kill_attempts": {"4242": 2},
        "processes": [
            {"pid": 1337, "ppid": 1, "name": "watcher", "active": True},
            {"pid": 4242, "ppid": 1337, "name": "hidden_shell", "active": False},
            {"pid": 4343, "ppid": 1337, "name": "hidden_shell", "active": True},
        ],
    }
    (tmp_path / "sim_state.json").write_text(json.dumps(state), encoding="utf-8")

    evaluator = MitigationEvaluator(tmp_path)
    feedback = evaluator.evaluate(
        "kill_process",
        {"ok": True, "message": "killed but respawned", "data": {"killed_pid": 4242, "respawned_pid": 4343}},
    )

    assert feedback.false_success is True
    assert feedback.success is False
    assert feedback.suggested_focus == "persistence"

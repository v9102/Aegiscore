"""Evaluator that validates whether mitigation actions actually worked."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EvaluationFeedback:
    """Structured evaluator feedback consumed by the reasoner."""

    success: bool
    false_success: bool
    reason: str
    suggested_focus: str | None = None


class MitigationEvaluator:
    """Re-check simulation state after each action to detect failed mitigation."""

    def __init__(self, simulation_dir: str | Path):
        self.state_file = Path(simulation_dir) / "sim_state.json"

    def _load_state(self) -> dict[str, Any]:
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def evaluate(self, tool_name: str, tool_result: dict[str, Any]) -> EvaluationFeedback:
        """Evaluate action result and detect false-success respawn cases."""

        state = self._load_state()

        if tool_name == "kill_process":
            data = tool_result.get("data", {})
            respawned_pid = data.get("respawned_pid")
            if respawned_pid is not None:
                respawn = next((p for p in state.get("processes", []) if p["pid"] == respawned_pid and p.get("active")), None)
                if respawn:
                    return EvaluationFeedback(
                        success=False,
                        false_success=True,
                        reason=f"PID changed via respawn under parent {respawn.get('ppid')}",
                        suggested_focus="persistence",
                    )
            if tool_result.get("ok"):
                return EvaluationFeedback(True, False, "Process mitigation appears successful")
            return EvaluationFeedback(False, False, tool_result.get("message", "kill failed"), "persistence")

        if tool_name == "block_ip":
            blocked_ips = state.get("blocked_ips", [])
            target_ip = tool_result.get("data", {}).get("ip")
            if target_ip in blocked_ips:
                return EvaluationFeedback(True, False, "IP containment confirmed")
            return EvaluationFeedback(False, False, "IP block not persisted", "containment")

        return EvaluationFeedback(bool(tool_result.get("ok")), False, tool_result.get("message", "action evaluated"))

"""Working memory for the reasoner loop."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkingMemory:
    """Short-lived in-memory state for decisions and adaptation."""

    actions_tried: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    pid_attempts: dict[int, int] = field(default_factory=dict)
    status: str = "idle"

    def add_action_outcome(self, action: str, success: bool, details: dict[str, Any]) -> None:
        """Append one action attempt and observed outcome."""

        self.actions_tried.append({"action": action, "success": success, "details": details})

    def add_hypothesis(self, hypothesis: str) -> None:
        """Store a hypothesis if it is not already tracked."""

        if hypothesis not in self.hypotheses:
            self.hypotheses.append(hypothesis)

    def record_pid_attempt(self, pid: int) -> None:
        """Track how many kill attempts were made for a specific PID."""

        self.pid_attempts[pid] = self.pid_attempts.get(pid, 0) + 1

    def get_pid_attempts(self, pid: int) -> int:
        """Return tracked kill attempts for a specific PID."""

        return self.pid_attempts.get(pid, 0)

    def summarize(self) -> str:
        """Summarize memory for provider prompts."""

        return json.dumps(
            {
                "status": self.status,
                "action_count": len(self.actions_tried),
                "actions_tried": self.actions_tried,
                "hypotheses": self.hypotheses or ["none"],
                "pid_attempts": self.pid_attempts,
            }
        )

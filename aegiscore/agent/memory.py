"""Working memory for the reasoner loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkingMemory:
    """Short-lived in-memory state for decisions and adaptation."""

    actions_tried: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    status: str = "idle"

    def add_action_outcome(self, action: str, success: bool, details: dict[str, Any]) -> None:
        """Append one action attempt and observed outcome."""

        self.actions_tried.append({"action": action, "success": success, "details": details})

    def add_hypothesis(self, hypothesis: str) -> None:
        """Store a hypothesis if it is not already tracked."""

        if hypothesis not in self.hypotheses:
            self.hypotheses.append(hypothesis)

    def summarize(self) -> str:
        """Summarize memory for provider prompts."""

        return (
            f"status={self.status}; "
            f"actions={len(self.actions_tried)}; "
            f"hypotheses={self.hypotheses or ['none']}"
        )

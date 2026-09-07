"""Reasoner loop implementing observe->decide->act->evaluate->adapt."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

from aegiscore.agent.memory import WorkingMemory
from aegiscore.agent.observer import Event
from aegiscore.agent.tools import SandboxTools
from aegiscore.evaluator.evaluator import EvaluationFeedback, MitigationEvaluator
from aegiscore.logsim.scenarios import MALICIOUS_PID, RESPAWN_PID, SUSPICIOUS_IPS


@dataclass
class ActionDecision:
    """Provider-selected next action."""

    tool: str
    args: dict[str, Any]
    rationale: str


class Provider(Protocol):
    """Swappable provider contract (OpenAI/Anthropic/mock)."""

    def decide(self, *, observations: list[Event], memory_summary: str, feedback: EvaluationFeedback | None) -> ActionDecision:
        ...


class MockProvider:
    """Fallback provider used when API keys are unavailable.

    TODO: replace with richer synthetic policy tuned for evaluation datasets.
    """

    def decide(self, *, observations: list[Event], memory_summary: str, feedback: EvaluationFeedback | None) -> ActionDecision:
        state = self._parse_memory_summary(memory_summary)
        actions_tried = state.get("actions_tried", [])
        pid_attempts = {int(pid): int(count) for pid, count in state.get("pid_attempts", {}).items()}
        first_ip = next((evt.source_ip for evt in observations if evt.source_ip), SUSPICIOUS_IPS[0])

        has_ip_reputation = any(action.get("action") == "check_ip_reputation" for action in actions_tried)
        if not has_ip_reputation:
            return ActionDecision("check_ip_reputation", {"ip": first_ip}, "Validate suspicious source reputation")

        malicious_attempts = pid_attempts.get(MALICIOUS_PID, 0)
        if malicious_attempts == 0:
            return ActionDecision("kill_process", {"pid": MALICIOUS_PID}, "Attempt first kill on hidden shell PID")

        if feedback and not feedback.success and feedback.suggested_focus == "persistence" and malicious_attempts == 1:
            return ActionDecision("find_parent_process", {"pid": MALICIOUS_PID}, "Investigate respawn parent after failed mitigation")

        if malicious_attempts == 1:
            return ActionDecision("kill_process", {"pid": MALICIOUS_PID}, "Retry kill on hidden shell PID")

        respawn_attempts = pid_attempts.get(RESPAWN_PID, 0)
        if respawn_attempts < 2:
            return ActionDecision("kill_process", {"pid": RESPAWN_PID}, "Contain respawned hidden shell PID")

        return ActionDecision("block_ip", {"ip": first_ip}, "Contain source after process mitigation")

    @staticmethod
    def _parse_memory_summary(memory_summary: str) -> dict[str, Any]:
        try:
            parsed = json.loads(memory_summary)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        return {}


class OpenAIProvider:
    """OpenAI-backed provider using tool/function-calling."""

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        from openai import OpenAI

        self.model = model
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set")
        self.client = OpenAI(api_key=self.api_key)

    def decide(self, *, observations: list[Event], memory_summary: str, feedback: EvaluationFeedback | None) -> ActionDecision:
        tools = [
            {"type": "function", "function": {"name": "check_ip_reputation", "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}}},
            {"type": "function", "function": {"name": "list_processes", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "inspect_process", "parameters": {"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]}}},
            {"type": "function", "function": {"name": "kill_process", "parameters": {"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]}}},
            {"type": "function", "function": {"name": "find_parent_process", "parameters": {"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]}}},
            {"type": "function", "function": {"name": "check_cron_jobs", "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "block_ip", "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}}},
        ]
        obs_summary = [evt.__dict__ for evt in observations[-15:]]
        feedback_blob = feedback.__dict__ if feedback else None
        prompt = (
            "You are an incident response planner. Pick exactly one next tool call that best advances "
            "the observe-decide-act-evaluate-adapt loop. Use evaluator feedback to adapt strategy and avoid repeating failed actions."
        )
        user_payload = {"observations": obs_summary, "memory": memory_summary, "feedback": feedback_blob}
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(user_payload)},
            ],
            tools=tools,
            tool_choice="auto",
        )
        message = response.choices[0].message
        if not message.tool_calls:
            raise ValueError("OpenAI provider returned no tool call")
        tool_call = message.tool_calls[0]
        args = json.loads(tool_call.function.arguments or "{}")
        rationale = message.content or "Model-selected tool call"
        return ActionDecision(tool_call.function.name, args, rationale)


class AnthropicProvider:
    """Anthropic-backed provider using Messages API tool use."""

    def __init__(self, model: str | None = None) -> None:
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set")
        from anthropic import Anthropic

        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
        self.client = Anthropic(api_key=self.api_key)

    def decide(self, *, observations: list[Event], memory_summary: str, feedback: EvaluationFeedback | None) -> ActionDecision:
        tools = [
            {
                "name": "check_ip_reputation",
                "description": "Check whether an IP appears malicious in local simulation intel",
                "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
            },
            {
                "name": "list_processes",
                "description": "List active processes in local simulation state",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "inspect_process",
                "description": "Inspect one process in local simulation state",
                "input_schema": {"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]},
            },
            {
                "name": "kill_process",
                "description": "Attempt simulated process kill in local simulation state",
                "input_schema": {"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]},
            },
            {
                "name": "find_parent_process",
                "description": "Find parent process for persistence investigation",
                "input_schema": {"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]},
            },
            {
                "name": "check_cron_jobs",
                "description": "Inspect simulated cron persistence points",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "block_ip",
                "description": "Simulate IP containment in local simulation state",
                "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
            },
        ]
        obs_summary = [evt.__dict__ for evt in observations[-15:]]
        feedback_blob = feedback.__dict__ if feedback else None
        prompt = (
            "You are an incident response planner. Pick exactly one next tool call that best advances "
            "the observe-decide-act-evaluate-adapt loop. Use evaluator feedback to adapt strategy and avoid repeating failed actions."
        )
        user_payload = {"observations": obs_summary, "memory": memory_summary, "feedback": feedback_blob}
        response = self.client.messages.create(
            model=self.model,
            max_tokens=512,
            system=prompt,
            tools=tools,
            messages=[{"role": "user", "content": json.dumps(user_payload)}],
        )

        tool_use_block = None
        rationale_parts: list[str] = []
        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "tool_use" and tool_use_block is None:
                tool_use_block = block
            if block_type == "text" and getattr(block, "text", None):
                rationale_parts.append(block.text)

        if tool_use_block is None:
            raise ValueError("Anthropic provider returned no tool use")

        args = dict(getattr(tool_use_block, "input", {}) or {})
        rationale = " ".join(rationale_parts).strip() or "Model-selected tool call"
        return ActionDecision(getattr(tool_use_block, "name"), args, rationale)


class AgentReasoner:
    """Class-based decision loop with full action audit trail."""

    def __init__(self, provider: Provider, tools: SandboxTools, evaluator: MitigationEvaluator, memory: WorkingMemory):
        self.provider = provider
        self.tools = tools
        self.evaluator = evaluator
        self.memory = memory
        self.action_log: list[dict[str, Any]] = []

    def run(self, observations: list[Event], max_steps: int = 5) -> None:
        """Run the observe->decide->act->evaluate->adapt loop."""

        feedback: EvaluationFeedback | None = None
        self.memory.status = "investigating"

        for _ in range(max_steps):
            decision = self.provider.decide(
                observations=observations,
                memory_summary=self.memory.summarize(),
                feedback=feedback,
            )
            self.action_log.append({"phase": "decide", "decision": decision.__dict__})
            if decision.tool == "kill_process" and "pid" in decision.args:
                self.memory.record_pid_attempt(int(decision.args["pid"]))

            tool_fn = getattr(self.tools, decision.tool)
            result = tool_fn(**decision.args)
            self.action_log.append({"phase": "act", "tool": decision.tool, "args": decision.args, "result": result.__dict__})

            feedback = self.evaluator.evaluate(decision.tool, result.__dict__)
            self.action_log.append({"phase": "evaluate", "feedback": feedback.__dict__})

            self.memory.add_action_outcome(decision.tool, feedback.success, feedback.__dict__)
            if feedback.suggested_focus:
                self.memory.add_hypothesis(feedback.suggested_focus)

            if feedback.success and decision.tool == "block_ip":
                self.memory.status = "contained"
                break


def build_provider() -> Provider:
    """Create live provider when key exists, otherwise mock mode."""

    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            return AnthropicProvider()
        except Exception:
            pass
    if os.getenv("OPENAI_API_KEY"):
        try:
            return OpenAIProvider()
        except Exception:
            return MockProvider()
    return MockProvider()

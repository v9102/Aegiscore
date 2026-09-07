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
        if feedback and not feedback.success and feedback.suggested_focus == "persistence":
            return ActionDecision("find_parent_process", {"pid": 4343}, "Investigate respawn parent after failed mitigation")
        if "actions=0" in memory_summary:
            first_ip = next((evt.source_ip for evt in observations if evt.source_ip), "203.0.113.10")
            return ActionDecision("check_ip_reputation", {"ip": first_ip}, "Validate suspicious source reputation")
        if "actions=1" in memory_summary:
            return ActionDecision("kill_process", {"pid": 4242}, "Attempt first kill on hidden shell PID")
        if "actions=2" in memory_summary:
            return ActionDecision("kill_process", {"pid": 4242}, "Retry kill after initial failure")
        if "actions=3" in memory_summary:
            return ActionDecision("kill_process", {"pid": 4343}, "Kill respawned child process")
        return ActionDecision("block_ip", {"ip": "203.0.113.10"}, "Contain source after process mitigation")


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
    """Optional Anthropic-backed provider placeholder."""

    def __init__(self) -> None:
        self.api_key = os.getenv("ANTHROPIC_API_KEY")

    def decide(self, *, observations: list[Event], memory_summary: str, feedback: EvaluationFeedback | None) -> ActionDecision:
        raise NotImplementedError("TODO: integrate Anthropic tool-calling provider")


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

    if os.getenv("OPENAI_API_KEY"):
        try:
            return OpenAIProvider()
        except Exception:
            return MockProvider()
    return MockProvider()

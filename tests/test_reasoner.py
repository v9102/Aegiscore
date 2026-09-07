from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

from aegiscore.agent.memory import WorkingMemory
from aegiscore.agent.observer import Event, read_simulation_events
from aegiscore.agent import reasoner as reasoner_module
from aegiscore.agent.reasoner import AgentReasoner, AnthropicProvider, MockProvider
from aegiscore.agent.tools import SandboxTools
from aegiscore.evaluator.evaluator import MitigationEvaluator
from aegiscore.logsim.generator import generate_scenario
from aegiscore.logsim.scenarios import MALICIOUS_PID, RESPAWN_PID


def test_mock_provider_reaches_containment_sequence(tmp_path: Path) -> None:
    generate_scenario(tmp_path)
    observations = read_simulation_events(tmp_path)
    reasoner = AgentReasoner(
        provider=MockProvider(),
        tools=SandboxTools(tmp_path),
        evaluator=MitigationEvaluator(tmp_path),
        memory=WorkingMemory(status="monitoring"),
    )

    reasoner.run(observations=observations, max_steps=10)

    actions = [entry["tool"] for entry in reasoner.action_log if entry["phase"] == "act"]
    assert actions == [
        "check_ip_reputation",
        "kill_process",
        "find_parent_process",
        "kill_process",
        "kill_process",
        "kill_process",
        "block_ip",
    ]
    assert reasoner.memory.get_pid_attempts(MALICIOUS_PID) == 2
    assert reasoner.memory.get_pid_attempts(RESPAWN_PID) == 2
    assert reasoner.memory.status == "contained"


def test_anthropic_provider_decide_parses_tool_use() -> None:
    provider = AnthropicProvider.__new__(AnthropicProvider)
    provider.model = "claude-sonnet-4-5"
    provider.client = SimpleNamespace(
        messages=SimpleNamespace(
            create=lambda **_: SimpleNamespace(
                content=[
                    SimpleNamespace(type="text", text="Contain by killing PID."),
                    SimpleNamespace(type="tool_use", name="kill_process", input={"pid": 4242}),
                ]
            )
        )
    )

    decision = provider.decide(
        observations=[Event("2026-01-01T00:00:00", "203.0.113.10", "ssh_failed", None, "line")],
        memory_summary='{"status":"investigating"}',
        feedback=None,
    )

    assert decision.tool == "kill_process"
    assert decision.args == {"pid": 4242}
    assert decision.rationale == "Contain by killing PID."


def test_build_provider_prioritizes_anthropic(monkeypatch) -> None:
    class DummyAnthropic:
        pass

    class DummyOpenAI:
        pass

    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setattr(reasoner_module, "AnthropicProvider", DummyAnthropic)
    monkeypatch.setattr(reasoner_module, "OpenAIProvider", DummyOpenAI)

    provider = reasoner_module.build_provider()
    assert isinstance(provider, DummyAnthropic)

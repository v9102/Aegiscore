"""End-to-end demo orchestration for AegisCore."""

from __future__ import annotations

from pathlib import Path

from aegiscore.agent.memory import WorkingMemory
from aegiscore.agent.observer import read_simulation_events
from aegiscore.agent.reasoner import AgentReasoner, build_provider
from aegiscore.agent.tools import SandboxTools
from aegiscore.evaluator.evaluator import MitigationEvaluator
from aegiscore.logsim.generator import generate_scenario


def run_demo(simulation_dir: str = "simulation") -> None:
    """Run deterministic scenario generation and the reasoner loop.

    TODO: expose richer CLI options for tuning loop behavior.
    """

    sim_path = Path(simulation_dir)
    generate_scenario(simulation_dir=sim_path)

    observations = read_simulation_events(sim_path)
    memory = WorkingMemory(status="monitoring")
    tools = SandboxTools(sim_path)
    evaluator = MitigationEvaluator(sim_path)

    reasoner = AgentReasoner(provider=build_provider(), tools=tools, evaluator=evaluator, memory=memory)
    reasoner.run(observations=observations, max_steps=5)

    print("\n=== AEGISCORE AUDIT TRAIL ===")
    for idx, item in enumerate(reasoner.action_log, start=1):
        print(f"{idx:02d}. {item}")


__all__ = ["run_demo"]

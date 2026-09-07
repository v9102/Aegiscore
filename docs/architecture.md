# AegisCore Architecture

AegisCore is scaffolded as a deterministic autonomous incident-response demo pipeline:

1. **Log Simulation (`aegiscore/logsim`)** creates a deterministic timeline with 50 SSH failures in 10 seconds, then hidden shell persistence behavior.
2. **Observer (`aegiscore/agent/observer.py`)** parses simulated `auth.log` and `access.log` lines into structured `Event` objects.
3. **Reasoner (`aegiscore/agent/reasoner.py`)** runs the observe → decide → act → evaluate → adapt loop with a swappable provider interface (mock/live-provider placeholders).
4. **Tools (`aegiscore/agent/tools.py`)** provide sandbox-local actions through a strict subprocess allowlist guard.
5. **Evaluator (`aegiscore/evaluator/evaluator.py`)** validates post-action state and flags false success (e.g., respawn under same parent PID).
6. **Memory (`aegiscore/agent/memory.py`)** tracks action outcomes, hypotheses, and status to inform adaptation.

Data flow is deterministic and local-only to support repeatable hackathon demos and judge verification.

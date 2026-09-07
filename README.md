# AegisCore — Autonomous Incident Responder

**Agentic AI Hackathon Submission | Tech Zephyr 4.0, IIT Bhubaneswar**

AegisCore is an autonomous agent that monitors simulated server logs, detects intrusion patterns, and executes a multi-step reasoning loop to neutralize threats — including recovering from a failed first mitigation attempt by diagnosing *why* it failed and adapting its strategy, rather than following a fixed playbook.

> Unlike traditional SOAR (Splunk SOAR, Cortex XSOAR, etc.), which executes pre-scripted playbooks for anticipated scenarios, AegisCore reasons through failure modes it wasn't explicitly programmed to handle.

---

## The Core Loop

```
OBSERVE → DECIDE → ACT → EVALUATE → ADAPT
```

1. **Observe** — Tails simulated log files (`auth.log`, Nginx access logs, process lists) and parses events
2. **Decide** — Classifies anomalies and chooses the next diagnostic/mitigation action
3. **Act** — Executes real system commands via a sandboxed, allowlisted tool set
4. **Evaluate** — Confirms the action actually worked (not just "command ran without error")
5. **Adapt** — On failure, forms a new hypothesis from the failure signal and changes strategy

---

## Demonstration Scenario

| Step | Event |
|---|---|
| 1 | Agent detects 50 SSH login attempts in 10s from one IP → flags anomaly, checks IP reputation |
| 2 | Agent detects an unauthorized shell process → attempts `kill -9 <PID>` |
| 3 | **Failure**: Permission denied / process respawns under a new PID |
| 4 | Agent evaluates the failure, hypothesizes a parent process or cron job is respawning it |
| 5 | Agent hunts the persistence mechanism (`find_parent_process`, `check_cron_jobs`) |
| 6 | Agent kills the parent/removes the cron entry, re-attempts kill on child, re-evaluates — confirmed dead |
| 7 | Agent blocks the offending IP via `iptables`; incident logged |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AegisCore Agent                      │
│  OBSERVE → DECIDE → ACT → EVALUATE → ADAPT (loop)           │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   Simulated Logs      IP Reputation API      Local Shell / OS
   (auth.log, nginx)   (AbuseIPDB or mock)     (ps, kill, iptables)
```

Full breakdown in [`docs/architecture.md`](docs/architecture.md).

---

## Project Structure

```
aegiscore/
├── logsim/          # Fake log generator + deterministic attack scenario
├── agent/           # Observer, LLM reasoning engine, memory, tool executor
├── evaluator/        # Confirms action outcomes, triggers adaptation
├── dashboard/        # (Optional) Next.js live decision-trace viewer
├── docker/           # Sandboxed container config
├── tests/
├── docs/
│   └── architecture.md
├── .env.example
├── requirements.txt
└── README.md
```

---

## Setup

### Prerequisites
- Python 3.11+
- Docker (recommended — keeps all agent actions sandboxed, never touching host system)
- An Anthropic or OpenAI API key

### Installation

```bash
git clone https://github.com/<your-username>/aegiscore.git
cd aegiscore
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # add your API key here — never commit .env
```

### Running the Demo Scenario

```bash
# 1. Start the sandboxed environment (Docker recommended)
docker build -t aegiscore -f docker/Dockerfile .
docker run -it --rm aegiscore

# 2. Generate the simulated attack (inside the container/sandbox)
python -m logsim.generator --scenario ssh_bruteforce_with_persistence

# 3. Run the agent
python -m agent.main
```

The agent will begin tailing the generated logs, detect the intrusion, attempt mitigation, hit the deliberate failure case, adapt, and resolve the incident. All decisions and tool calls are printed to the console and logged to `logs/agent_actions.log`.

### Reproducing the Failure Case for Judges

The attack scenario in `logsim/scenarios.py::ssh_bruteforce_with_persistence` is fully deterministic: killing the malicious process always fails on the first attempt (simulated permission denial / respawn under a new PID via a parent watcher process), forcing the agent to diagnose and hunt the persistence mechanism. Re-run the same command above to reproduce identically.

---

## Safety Notes

- All actions execute against a **sandboxed Docker container / local VM only** — never real infrastructure
- Tool execution is restricted to a **hard-coded allowlist** (`agent/tools.py`) — the agent cannot run arbitrary shell commands
- Logs and attacks are **simulated**, not captured from live network traffic
- Every decision and command is written to an audit trail (`logs/agent_actions.log`) for transparency

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent core | Python |
| Reasoning | Anthropic/OpenAI API (tool-calling) |
| System execution | `subprocess` (bash) |
| Log simulation | Python |
| Dashboard (optional) | Next.js + Tailwind |
| Deployment | Docker |

---

## Team

_Add team member names and roles here._

## License

_Add license here (e.g., MIT), if applicable._

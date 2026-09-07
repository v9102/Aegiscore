# AegisCore

AegisCore is a sandbox-only autonomous incident-response scaffold for deterministic hackathon demos.

## Overview

This scaffold demonstrates an end-to-end loop:

`log simulation -> observation -> reasoning -> tool invocation -> evaluation -> adaptation`

It is intentionally local/simulated and not production-ready.

## Setup

- Python 3.11+
- Optional Docker

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Run deterministic log generation

```bash
python -m aegiscore.logsim.generator --scenario ssh_bruteforce_with_persistence --output-dir simulation
```

This writes deterministic `auth.log`, `access.log`, and `sim_state.json` artifacts.

## Run the full agent demo locally

```bash
python -m aegiscore
```

The demo runs in mock-provider mode by default and prints an audit trail of decisions, actions, tool results, and evaluator feedback.

## Reproduce deliberate first mitigation failure

The built-in deterministic scenario always forces initial kill failure behavior:

- first kill attempt returns permission denied, then
- follow-up mitigation can show hidden-shell respawn behavior under the same parent.

Re-run the same generator command to reproduce the same timeline and failure conditions.

## Mock mode vs live LLM mode

- **Mock mode**: works without API keys and is runnable immediately.
- **Live mode placeholders**: swappable provider classes for OpenAI/Anthropic are scaffolded with TODOs for tool-calling integration.

## Audit trail output

The reasoner maintains `action_log` entries for:

- decision rationale,
- tool call + arguments,
- tool result,
- evaluator feedback/adaptation signal.

## Safety notes

- Sandbox-only intent; non-production usage.
- `kill_process` and `block_ip` are simulated by mutating local `simulation/sim_state.json` state, not by killing host processes or changing host firewall rules.
- Command execution is constrained by a strict allowlist helper in `aegiscore/agent/tools.py`; only safe local commands (`cat`, `echo`, `true`) are permitted.

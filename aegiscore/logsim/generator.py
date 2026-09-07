"""Generate deterministic simulated logs for AegisCore."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegiscore.logsim.scenarios import (
    MALICIOUS_PARENT_PID,
    MALICIOUS_PID,
    RESPAWN_PID,
    SUSPICIOUS_IPS,
    build_ssh_bruteforce_with_persistence,
)


def generate_scenario(simulation_dir: str | Path, scenario: str = "ssh_bruteforce_with_persistence") -> None:
    """Write deterministic auth/access logs and simulation state files.

    TODO: emit richer and noisier log lines for stronger parser hardening tests.
    """

    if scenario != "ssh_bruteforce_with_persistence":
        raise ValueError(f"Unsupported scenario: {scenario}")

    out_dir = Path(simulation_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    auth_log = out_dir / "auth.log"
    access_log = out_dir / "access.log"
    state_file = out_dir / "sim_state.json"

    auth_lines: list[str] = []
    access_lines: list[str] = []

    for event in build_ssh_bruteforce_with_persistence():
        if event.channel == "auth":
            if event.event_type == "ssh_failed":
                auth_lines.append(
                    f"{event.timestamp} sshd Failed password for {event.payload['username']} from {event.payload['source_ip']} port 22"
                )
            elif event.event_type == "process_spawn":
                auth_lines.append(
                    f"{event.timestamp} process hidden_shell pid={event.payload['pid']} ppid={event.payload['ppid']}"
                )
            elif event.event_type == "kill_denied":
                auth_lines.append(
                    f"{event.timestamp} kernel kill pid={event.payload['pid']} denied reason={event.payload['reason']}"
                )
            elif event.event_type == "process_respawned":
                auth_lines.append(
                    f"{event.timestamp} process hidden_shell respawn old_pid={event.payload['old_pid']} pid={event.payload['pid']} ppid={event.payload['ppid']}"
                )
        elif event.channel == "access":
            access_lines.append(
                f"{event.timestamp} {event.payload['source_ip']} GET {event.payload['path']} 404"
            )

    auth_log.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    access_log.write_text("\n".join(access_lines) + "\n", encoding="utf-8")

    sim_state = {
        "blocked_ips": [],
        "kill_attempts": {},
        "known_bad_ips": list(SUSPICIOUS_IPS),
        "processes": [
            {"pid": MALICIOUS_PARENT_PID, "ppid": 1, "name": "watcher", "active": True},
            {"pid": MALICIOUS_PID, "ppid": MALICIOUS_PARENT_PID, "name": "hidden_shell", "active": True},
            {"pid": RESPAWN_PID, "ppid": MALICIOUS_PARENT_PID, "name": "hidden_shell", "active": False},
        ],
    }
    state_file.write_text(json.dumps(sim_state, indent=2), encoding="utf-8")


def main() -> None:
    """CLI entry for deterministic scenario artifact generation."""

    parser = argparse.ArgumentParser(description="Generate deterministic AegisCore simulation logs")
    parser.add_argument("--scenario", default="ssh_bruteforce_with_persistence")
    parser.add_argument("--output-dir", default="simulation")
    args = parser.parse_args()

    generate_scenario(simulation_dir=args.output_dir, scenario=args.scenario)
    print(f"Generated deterministic scenario '{args.scenario}' at {args.output_dir}")


if __name__ == "__main__":
    main()

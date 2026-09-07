"""Sandbox-only tool implementations for AegisCore."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ToolResult:
    """Result object returned by all tools."""

    ok: bool
    message: str
    data: dict[str, Any]


def run_allowlisted_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run command only if it is in hard-coded allowlist and shell-free.

    TODO: Replace command-level stubs with richer local simulation executors.
    """

    allowed_binaries = {"cat", "echo", "true"}
    if not command or command[0] not in allowed_binaries:
        raise ValueError(f"Command not allowed: {command}")
    return subprocess.run(command, check=True, text=True, capture_output=True)


class SandboxTools:
    """Tool call surface used by the reasoner."""

    def __init__(self, simulation_dir: str | Path):
        self.simulation_dir = Path(simulation_dir)
        self.state_file = self.simulation_dir / "sim_state.json"

    def _load_state(self) -> dict[str, Any]:
        output = run_allowlisted_command(["cat", str(self.state_file)]).stdout
        return json.loads(output)

    def _save_state(self, state: dict[str, Any]) -> None:
        self.state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def check_ip_reputation(self, ip: str) -> ToolResult:
        state = self._load_state()
        bad = ip in state.get("known_bad_ips", [])
        return ToolResult(True, "IP reputation checked", {"ip": ip, "is_suspicious": bad})

    def list_processes(self) -> ToolResult:
        state = self._load_state()
        processes = [p for p in state.get("processes", []) if p.get("active")]
        return ToolResult(True, "Listed active processes", {"processes": processes})

    def inspect_process(self, pid: int) -> ToolResult:
        state = self._load_state()
        for process in state.get("processes", []):
            if process["pid"] == pid:
                return ToolResult(True, "Inspected process", {"process": process})
        return ToolResult(False, "PID not found", {"pid": pid})

    def kill_process(self, pid: int) -> ToolResult:
        state = self._load_state()
        attempts = state.setdefault("kill_attempts", {})
        attempt_count = attempts.get(str(pid), 0) + 1
        attempts[str(pid)] = attempt_count

        if attempt_count == 1:
            return ToolResult(False, "permission denied", {"pid": pid, "attempt": attempt_count})

        target = next((p for p in state.get("processes", []) if p["pid"] == pid), None)
        if not target:
            return ToolResult(False, "PID not found", {"pid": pid})

        target["active"] = False

        if target.get("name") == "hidden_shell":
            respawn = next((p for p in state["processes"] if p["pid"] == 4343), None)
            if respawn and not respawn.get("active"):
                respawn["active"] = True
                self._save_state(state)
                return ToolResult(True, "killed but respawned", {"killed_pid": pid, "respawned_pid": 4343})

        self._save_state(state)
        return ToolResult(True, "Process killed", {"pid": pid})

    def find_parent_process(self, pid: int) -> ToolResult:
        state = self._load_state()
        target = next((p for p in state.get("processes", []) if p["pid"] == pid), None)
        if not target:
            return ToolResult(False, "PID not found", {"pid": pid})
        parent = next((p for p in state.get("processes", []) if p["pid"] == target["ppid"]), None)
        return ToolResult(True, "Parent lookup completed", {"pid": pid, "parent": parent})

    def check_cron_jobs(self) -> ToolResult:
        run_allowlisted_command(["echo", "TODO: simulated cron inspection"])  # nosec B603
        return ToolResult(True, "No suspicious cron jobs found in scaffold", {"jobs": []})

    def block_ip(self, ip: str) -> ToolResult:
        state = self._load_state()
        blocked = state.setdefault("blocked_ips", [])
        if ip not in blocked:
            blocked.append(ip)
            self._save_state(state)
        return ToolResult(True, "IP blocked in local simulation state", {"ip": ip, "blocked_ips": blocked})

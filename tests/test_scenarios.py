from aegiscore.logsim.scenarios import build_ssh_bruteforce_with_persistence


def test_scenario_is_deterministic() -> None:
    first = [event.__dict__ for event in build_ssh_bruteforce_with_persistence()]
    second = [event.__dict__ for event in build_ssh_bruteforce_with_persistence()]
    assert first == second
    assert len([e for e in first if e["event_type"] == "ssh_failed"]) == 50

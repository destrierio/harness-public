"""End-to-end proof: the real harness loop captures a flag by actually running the
exploit against a live (local) target, and does NOT capture when it skips the
exploit path (the mutation check)."""
import pytest

import harness.gateway as gateway_module
from testrig.run_local import (
    exploit_script, noexploit_script, run_against_rig, run_delegate_rig, run_session_rig,
)


def test_agent_captures_flag_end_to_end():
    result = run_against_rig(exploit_script)
    assert result.flags_captured == 1
    assert result.reason in ("cost_exhausted", "deadline")  # never a crash


def test_no_exploit_does_not_capture():
    # Mutation check: the flag is reachable only through ?file=../flag. A run that
    # curls the landing page and guesses a flag must capture nothing.
    result = run_against_rig(noexploit_script)
    assert result.flags_captured == 0


@pytest.mark.parametrize("rig", [
    lambda: run_against_rig(exploit_script), run_session_rig, run_delegate_rig,
], ids=["shell", "session", "delegate"])
def test_local_rigs_honor_config_output_limit(tmp_path, monkeypatch, rig):
    # A one-character tool limit removes the flag before the loop can scan it.
    # Loading defaults instead of the selected YAML incorrectly captures it.
    config = tmp_path / "config.yaml"
    config.write_text("tools:\n  shell_output_limit: 1\n")
    monkeypatch.setenv("HARNESS_CONFIG", str(config))
    result = rig()
    assert result.flags_captured == 0


@pytest.mark.parametrize("rig", [
    lambda: run_against_rig(exploit_script), run_session_rig, run_delegate_rig,
], ids=["shell", "session", "delegate"])
def test_local_rigs_honor_gateway_resilience_settings(tmp_path, monkeypatch, rig):
    config = tmp_path / "config.yaml"
    # More headroom than the rig's 60-second budget prevents any retry.
    config.write_text("strategy:\n  retry_headroom_seconds: 70\n  model_call_timeout_seconds: 2.5\n")
    monkeypatch.setenv("HARNESS_CONFIG", str(config))
    transport = gateway_module._urllib_transport
    timeouts = []

    def fail_once(url, headers, body, timeout=None):
        timeouts.append(timeout)
        if len(timeouts) == 1:
            return 503, b"temporarily unavailable"
        return transport(url, headers, body, timeout=timeout)

    monkeypatch.setattr(gateway_module, "_urllib_transport", fail_once)
    result = rig()
    assert result.reason == "deadline"
    assert result.flags_captured == 0
    assert timeouts == [2.5]

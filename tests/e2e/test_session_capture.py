"""End-to-end proof of the session tool: the real loop holds an `nc` session to a
TCP service, sends the command that reveals the flag, and captures it. Mutation
check: sending the wrong command captures nothing."""
from testrig.run_local import run_session_rig, session_noexploit_script


def test_agent_captures_flag_via_session():
    result = run_session_rig()
    assert result.flags_captured == 1
    assert result.reason in ("cost_exhausted", "deadline")


def test_wrong_command_over_session_does_not_capture():
    result = run_session_rig(session_noexploit_script)
    assert result.flags_captured == 0

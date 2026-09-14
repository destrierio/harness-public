"""End-to-end proof of delegation: the orchestrator hands the goal to the web
specialist, which runs the exploit in its own context and captures the flag; the
capture (shared KB + submitter) is visible to the whole run."""
from testrig.run_local import run_delegate_rig


def test_orchestrator_delegates_and_specialist_captures():
    result = run_delegate_rig()
    assert result.flags_captured == 1
    assert result.reason in ("cost_exhausted", "deadline")

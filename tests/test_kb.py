from harness.kb import KB
from helpers import _ctx


def test_digest_includes_findings_and_creds():
    kb = KB()
    kb.record_service(host="box", port=80, proto="tcp", product="nginx", version="1.25", notes="")
    kb.record_finding(
        host="box", service="80/tcp", cls="lfi", status="confirmed",
        evidence="?file=../", next_action="read flag",
    )
    kb.record_credential(value="admin:admin", where_found="login", works_on="80", privilege="user")
    d = kb.situation_digest(_ctx(), seconds_left=900, tokens=1234)
    assert "lfi" in d
    assert "admin:admin" in d
    assert "900" in d
    assert "get root" in d  # the objective


def test_fingerprint_changes_when_state_changes():
    kb = KB()
    f0 = kb.fingerprint()
    kb.record_service(host="box", port=22, proto="tcp", product="openssh", version="9", notes="")
    assert kb.fingerprint() != f0


def test_dead_ends_are_recorded_and_shown():
    kb = KB()
    kb.mark_dead("gobuster on / found nothing")
    d = kb.situation_digest(_ctx(), seconds_left=10, tokens=1)
    assert "gobuster" in d


def test_confirmed_findings_rank_above_suspected():
    kb = KB()
    kb.record_finding(host="b", service="s", cls="weak-suspect", status="suspected", evidence="", next_action="")
    kb.record_finding(host="b", service="s", cls="strong-confirm", status="confirmed", evidence="", next_action="")
    d = kb.situation_digest(_ctx(), seconds_left=10, tokens=1)
    assert d.index("strong-confirm") < d.index("weak-suspect")


def test_set_plan_coerces_and_replaces():
    from harness.kb import KB, PlanStep
    kb = KB()
    kb.set_plan([{"goal": "enumerate web", "status": "done"},
                 {"goal": "try default creds", "status": "active", "note": "admin panel"},
                 {"bogus": "ignored"}])
    assert [type(s) for s in kb.plan] == [PlanStep, PlanStep, PlanStep]
    assert kb.plan[1].goal == "try default creds" and kb.plan[1].status == "active"
    assert kb.plan[2].goal == ""  # missing goal coerced, not fatal
    kb.set_plan([{"goal": "only one now"}])
    assert len(kb.plan) == 1 and kb.plan[0].status == "open"  # default status


def test_situation_digest_renders_plan_when_present():
    from harness.kb import KB
    from helpers import _ctx
    kb = KB()
    kb.set_plan([{"goal": "try default creds", "status": "active", "note": "admin panel"}])
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=1)
    assert "PLAN" in out
    assert "try default creds" in out and "admin panel" in out


def test_situation_digest_no_plan_section_when_empty():
    from harness.kb import KB
    from helpers import _ctx
    out = KB().situation_digest(_ctx(), seconds_left=100, tokens=1)
    assert "PLAN" not in out


def test_situation_digest_renders_progress_log():
    from harness.kb import KB
    from helpers import _ctx
    kb = KB()
    kb.progress_log = "Tried default creds on :80 (failed). Found /admin login."
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=1)
    assert "PROGRESS LOG" in out and "/admin login" in out


def test_situation_digest_renders_notes_when_present():
    # The model's durable scratchpad: byte-level RE state that no typed field holds
    # (offsets, opcode/state tables, VERIFIED-vs-PLANTED verdicts). It must appear in
    # the digest so a transcript trim never loses it and the model stops re-emitting it.
    kb = KB()
    kb.set_notes("example-service frame: magic 0x12345678; 0x1200 state table 0->0x1300; "
                 "example.ini token demo = PLANTED (port 9999 closed)")
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=1)
    assert "NOTES" in out
    assert "0x1200 state table" in out and "PLANTED" in out


def test_situation_digest_no_notes_section_when_empty():
    assert "NOTES" not in KB().situation_digest(_ctx(), seconds_left=100, tokens=1)


def test_set_notes_replaces_whole_scratchpad():
    kb = KB()
    kb.set_notes("first draft")
    kb.set_notes("second draft")
    assert kb.notes == "second draft"


def test_notes_are_durable_state_in_the_fingerprint():
    # A notes update is real progress (state changed) — it must move the fingerprint so
    # the loop does not read an active RE turn as a stall.
    kb = KB()
    f0 = kb.fingerprint()
    kb.set_notes("recovered the measurement magic 0x5710")
    assert kb.fingerprint() != f0


def test_budget_line_hidden_when_show_budget_false():
    from harness.kb import KB
    from helpers import _ctx
    shown = KB().situation_digest(_ctx(), seconds_left=100, tokens=7, show_budget=True)
    hidden = KB().situation_digest(_ctx(), seconds_left=100, tokens=7, show_budget=False)
    assert "Budget:" in shown
    assert "Budget:" not in hidden


def test_record_host_and_network_digest_section():
    from harness.kb import KB
    from helpers import _ctx
    kb = KB()
    kb.record_host(address="10.0.1.9", hostname="vault", reachable_via="foothold")
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=1)
    assert "Network:" in out
    assert "10.0.1.9" in out and "vault" in out and "via foothold" in out

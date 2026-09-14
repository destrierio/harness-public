"""Coverage checklist + win-sequencing: an explicit, adaptive view of which vectors
have been tried on the active surface (so a stall points at the best UNTRIED one),
and a state-aware CURRENT GOAL that pursues the nearest win first."""
from harness.coverage import (
    AUTH_VECTORS,
    HOST_VECTORS,
    PWN_VECTORS,
    WEB_VECTORS,
    coverage_report,
)
from harness.kb import KB, staged_goal
from harness.loop import _coverage_nudge
from helpers import _ctx


# --- surface selection follows the phase -----------------------------------

def test_no_services_no_foothold_yields_no_checklist():
    text, untried = coverage_report(KB(), "foothold")
    assert text is None and untried == []


def test_web_service_selects_web_surface():
    kb = KB()
    kb.record_service(host="box", port=80, product="Boa httpd")
    text, untried = coverage_report(kb, "foothold")
    assert "web entry" in text
    assert untried == WEB_VECTORS  # all untried at the start, in priority order


def test_auth_only_service_selects_auth_surface():
    kb = KB()
    kb.record_service(host="box", port=22, product="OpenSSH")
    text, untried = coverage_report(kb, "foothold")
    assert "auth-service entry" in text
    assert untried == AUTH_VECTORS


def test_foothold_switches_to_host_surface():
    kb = KB()
    kb.record_service(host="box", port=80, product="nginx")
    kb.record_access(host="box", session="foothold", user="www-data", privilege="user")
    text, untried = coverage_report(kb, "privesc")
    assert "privilege-escalation" in text
    assert untried == HOST_VECTORS  # way-up checklist, not way-in


def test_pwn_objective_without_services_selects_binary():
    text, untried = coverage_report(KB(), "pwn")
    assert "binary" in text
    assert untried == PWN_VECTORS


# --- status is derived from recorded findings ------------------------------

def test_tried_and_dead_vectors_drop_out_of_untried():
    kb = KB()
    kb.record_service(host="box", port=80, product="Apache")
    kb.record_finding(host="box", cls="LFI via ?file= path traversal", status="dead")
    kb.record_finding(host="box", cls="SQL injection on login", status="confirmed")
    text, untried = coverage_report(kb, "foothold")
    assert "lfi-rfi" not in untried            # tried-and-failed: not suggested again
    assert "sqli" not in untried               # already landed
    assert "dead (don't retry): lfi-rfi" in text
    assert "landed: sqli" in text
    assert "default-creds" in untried          # genuinely untried remains, in priority order
    assert untried[0] == "default-creds"


def test_coverage_nudge_names_untried_vectors():
    nudge = _coverage_nudge(["default-creds", "known-cve", "sqli"])
    assert nudge["role"] == "user"
    assert "default-creds" in nudge["content"] and "known-cve" in nudge["content"]


# --- win-sequencing: nearest win first -------------------------------------

def test_staged_goal_privesc_without_foothold_targets_the_foothold():
    goal = staged_goal("escalate to root and read the flag", KB())
    assert "stage 1" in goal.lower()
    assert "foothold" in goal.lower()
    assert "do not hunt the root" in goal.lower()


def test_staged_goal_privesc_with_user_foothold_says_escalate():
    kb = KB()
    kb.record_access(host="box", session="foothold", user="www-data", privilege="user")
    goal = staged_goal("get root", kb)
    assert "stage 2" in goal.lower()
    assert "escalate" in goal.lower()


def test_staged_goal_when_privilege_satisfied_says_read_flag():
    kb = KB()
    kb.record_access(host="box", session="foothold", user="root", privilege="root")
    goal = staged_goal("get root", kb)
    assert "read and submit the flag" in goal.lower()


def test_staged_goal_foothold_objective_without_access_targets_access():
    goal = staged_goal("gain a foothold as the service-user", KB())
    assert "gain access" in goal.lower()


def test_digest_renders_coverage_block():
    kb = KB()
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=1,
                              coverage="Coverage — web entry\n  UNTRIED: default-creds, known-cve")
    assert "Coverage — web entry" in out
    assert "UNTRIED: default-creds" in out

"""Focus-discipline coverage (P1-P3, P6 + the LEARNINGS closers): objective
classification, history trimming, the turn guard, the commit nudge, and the
auto-loot sweep that runs the boring flag hunt the moment a foothold lands."""
import json

from harness.config import Config
from harness.gateway import ChatResult, CostExhausted
from harness.kb import KB, classify_objective, win_condition_text
from harness.loop import (
    _TurnGuard,
    _auto_loot,
    _foothold_session_names,
    _is_recon_command,
    _should_commit,
    _trim_history,
    run,
)
from harness.tools import ToolExecutor
from helpers import _ctx, _fake_submitter


def _cfg(**strategy):
    return Config(models={}, prompts={}, strategy=dict(strategy), sampling={}, tools={})


# --- P6: objective classification -----------------------------------------

def test_classify_objective_buckets():
    assert classify_objective("gain a foothold as the service-user") == "foothold"
    assert classify_objective("escalate to root and read the flag") == "privesc"
    assert classify_objective("read the flag from the web app") == "flag_file"
    assert classify_objective("exploit the binary with a ROP chain") == "pwn"
    assert classify_objective("do the thing") == "generic"


def test_win_condition_text_present_for_foothold_absent_for_generic():
    assert "FOOTHOLD" in (win_condition_text("get a foothold as svc") or "")
    assert win_condition_text("something vague") is None


# --- P3: history trimming keeps assistant->tool pairing --------------------

def _turn(idx):
    return [
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": f"c{idx}", "type": "function",
                         "function": {"name": "shell", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": f"c{idx}", "content": f"out{idx}"},
    ]


def test_trim_history_keeps_last_n_turns_and_starts_at_assistant():
    history = []
    for i in range(6):
        history += _turn(i)
    trimmed = _trim_history(history, 2)
    assert trimmed[0]["role"] == "assistant"          # starts on a boundary (valid pairing)
    assert [m for m in trimmed if m["role"] == "assistant"].__len__() == 2
    assert trimmed[-1]["content"] == "out5"            # newest kept


def test_trim_history_zero_is_unlimited():
    history = []
    for i in range(4):
        history += _turn(i)
    assert _trim_history(history, 0) is history


# --- LEARNINGS: refuse repeats + stop scanning after a foothold ------------

def test_is_recon_command_detects_scanners():
    assert _is_recon_command("nmap -sT -Pn box")
    assert _is_recon_command("sudo /usr/bin/gobuster dir -u http://box")
    assert not _is_recon_command("cat /etc/passwd")


def test_guard_refuses_exact_repeat():
    g = _TurnGuard(KB(), refuse_repeats=True, focus_after_foothold=False)
    assert g("shell", {"command": "id"}) is None          # first run allowed
    assert "REFUSED" in g("shell", {"command": "id"})      # exact repeat refused
    assert g("shell", {"command": "whoami"}) is None       # a different command is fine


def test_guard_refuses_rescan_after_foothold():
    kb = KB()
    g = _TurnGuard(kb, refuse_repeats=False, focus_after_foothold=True)
    assert g("shell", {"command": "nmap -sT box"}) is None  # no foothold yet: allowed
    kb.record_access(host="box", session="foothold", user="root")
    assert "REFUSED" in g("shell", {"command": "nmap -sT box"})  # now refused
    assert g("shell", {"command": "cat /flag"}) is None          # non-scan still allowed


# --- P2: commit-to-exploit signal ------------------------------------------

def test_should_commit_only_with_creds_lead_and_no_foothold():
    kb = KB()
    assert not _should_commit(kb)
    kb.record_credential(value="admin:admin")
    assert not _should_commit(kb)                      # creds but no lead
    kb.record_finding(host="box", cls="cve", status="suspected")
    assert _should_commit(kb)                          # creds + lead, no foothold
    kb.record_access(host="box", session="foothold")
    assert not _should_commit(kb)                      # already in: nothing to commit to


# --- LEARNINGS: auto-loot the moment a foothold lands ----------------------

class _FakeSessions:
    def __init__(self, outputs):
        self._outputs = list(outputs)
        self.sent = []

    def has(self, name):
        return name == "foothold"

    def send(self, name, data, timeout=2.0):
        self.sent.append((name, data))
        return self._outputs.pop(0) if self._outputs else ""

    def list(self):
        return ["foothold"]

    def close_all(self):
        pass


def test_auto_loot_runs_sweep_and_submits_printed_flag():
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg(),
                      sessions=_FakeSessions(["uid=0(root)", "== /flag ==\ndestrier{loot_1}", ""]))
    sub = _fake_submitter()
    text = _auto_loot(ex, "foothold", sub)
    assert "destrier{loot_1}" in text
    assert "destrier{loot_1}" in sub.captured          # scanned + submitted during the sweep
    assert len(ex._sessions.sent) == 3                 # the full generic sweep ran


class _ScriptedGateway:
    def __init__(self, script):
        self.script = list(script)
        self.total_tokens = 0

    def chat(self, model, messages, *, tools=None, now, **kw):
        if not self.script:
            raise CostExhausted("drained")
        return self.script.pop(0)


def test_loop_auto_loots_on_recorded_foothold():
    kb = KB()
    sub = _fake_submitter()
    sessions = _FakeSessions(["uid=0(root)", "cat: nope", "== flag ==\ndestrier{closed_9}"])
    ex = ToolExecutor(_ctx(), kb, sub, _cfg(), sessions=sessions)
    access_call = [{"id": "a1", "type": "function", "function": {
        "name": "record_access",
        "arguments": json.dumps({"host": "box", "session": "foothold",
                                 "user": "root", "privilege": "root", "how": "ssh"})}}]
    gw = _ScriptedGateway([ChatResult(content=None, tool_calls=access_call,
                                      finish_reason="tool_calls", total_tokens=1)])
    res = run(_ctx(), _cfg(auto_loot_on_foothold=True), gateway=gw,
              submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert res.reason == "cost_exhausted"
    assert "destrier{closed_9}" in sub.captured        # the closer: harness found the flag
    assert sessions.sent                               # the sweep actually ran in the session


def test_loop_without_auto_loot_does_not_sweep():
    kb = KB()
    sub = _fake_submitter()
    sessions = _FakeSessions(["uid=0(root)", "x", "destrier{should_not_9}"])
    ex = ToolExecutor(_ctx(), kb, sub, _cfg(), sessions=sessions)
    access_call = [{"id": "a1", "type": "function", "function": {
        "name": "record_access",
        "arguments": json.dumps({"host": "box", "session": "foothold"})}}]
    gw = _ScriptedGateway([ChatResult(content=None, tool_calls=access_call,
                                      finish_reason="tool_calls", total_tokens=1)])
    run(_ctx(), _cfg(), gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert not sessions.sent                           # off by default: no sweep


def test_foothold_session_names_includes_revshell():
    kb = KB()
    kb.record_access(host="box", session="foothold")
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), _cfg(), sessions=_FakeSessions([]))
    assert _foothold_session_names(kb, ex) == ["foothold"]


def test_auto_loot_hunts_user_txt_and_common_flag_files():
    # a regression run: the flag was /home/dev/user.txt but the sweep globbed only
    # /home/*/flag*, so it was never even cat'd. user.txt/root.txt must be covered.
    sessions = _FakeSessions(["uid=1000(dev)", "== /home/dev/user.txt ==\ndestrier{u_1}", ""])
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg(), sessions=sessions)
    sub = _fake_submitter()
    _auto_loot(ex, "foothold", sub)
    sent = " ".join(cmd for _n, cmd in sessions.sent)
    assert "user.txt" in sent and "root.txt" in sent
    assert "destrier{u_1}" in sub.captured


def test_loop_reloots_a_session_after_escalating_to_a_new_user():
    # a regression run: only the postgres foothold was recorded; the agent su'd to dev but
    # auto-loot never re-ran as dev, so /home/dev/user.txt (readable only by dev) was
    # left unread. Recording the escalated shell must trigger a fresh loot as that user.
    kb = KB()
    sub = _fake_submitter()
    sessions = _FakeSessions([
        "uid=100(postgres)", "no flag readable as postgres", "",       # loot 1 (postgres)
        "uid=1000(dev)", "== user.txt ==\ndestrier{dev_flag_1}", "",   # loot 2 (dev, re-loot)
    ])
    ex = ToolExecutor(_ctx(), kb, sub, _cfg(), sessions=sessions)

    def _rec(user, priv):
        return [{"id": "a", "type": "function", "function": {
            "name": "record_access",
            "arguments": json.dumps({"host": "box", "session": "foothold",
                                     "user": user, "privilege": priv, "how": "x"})}}]

    gw = _ScriptedGateway([
        ChatResult(content=None, tool_calls=_rec("postgres", "user"), finish_reason="tool_calls", total_tokens=1),
        ChatResult(content=None, tool_calls=_rec("dev", "user"), finish_reason="tool_calls", total_tokens=1),
    ])
    run(_ctx(), _cfg(auto_loot_on_foothold=True), gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert "destrier{dev_flag_1}" in sub.captured   # the re-loot as dev grabbed the user flag


# --- P6: digest surfaces the win condition and foothold banner -------------

def test_digest_shows_win_condition_and_foothold_mode():
    kb = KB()
    kb.record_access(host="box", session="foothold", user="svc", privilege="user")
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=5,
                              win_condition="OBJECTIVE TYPE: FOOTHOLD.", foothold_focus=True)
    assert "OBJECTIVE TYPE: FOOTHOLD." in out
    assert "FOOTHOLD MODE" in out


def test_digest_unchanged_when_options_absent():
    kb = KB()
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=5)
    assert "FOOTHOLD MODE" not in out
    assert "OBJECTIVE TYPE" not in out


def test_unverified_access_does_not_trip_foothold_mode_or_guard():
    from harness.kb import KB, Access
    from harness.loop import _TurnGuard
    kb = KB()
    kb.accesses.append(Access(host="box", session="foothold", user="?", verified=False))
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=1, foothold_focus=True)
    assert "FOOTHOLD MODE" not in out
    assert "UNVERIFIED" in out
    g = _TurnGuard(kb, refuse_repeats=False, focus_after_foothold=True)
    assert g("shell", {"command": "nmap -sT box"}) is None


# --- Race lock-in: pin a tool-confirmed double-fetch verdict in the digest ------------
# When re_emulate DETERMINISTICALLY confirms a check-then-commit / double-fetch race, the
# model must not be able to argue it away with noisy local-lab results and revert to
# constructing a static frame (a regression run did exactly that, dropping the verdict). The
# harness pins the emulator's verdict into the SITUATION every turn as an un-overridable fact.

def test_digest_pins_a_confirmed_race_verdict_prominently():
    kb = KB()
    kb.race_verdict = (
        "RACE (double-fetch / TOCTOU) — NOT statically solvable.\n"
        "  field [+0x08] is required to equal 0xaaaa1111 and 0xbbbb2222 at different reads.")
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=5)
    assert "RACE (double-fetch / TOCTOU)" in out
    assert "CONFIRMED BY EMULATOR" in out          # pinned as an un-overridable tool verdict
    assert "MAP_SHARED" in out                      # the concurrent-build instruction is present


def test_digest_has_no_race_block_when_absent():
    kb = KB()
    out = kb.situation_digest(_ctx(), seconds_left=100, tokens=5)
    assert "CONFIRMED BY EMULATOR" not in out

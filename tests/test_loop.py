import subprocess

from harness.gateway import ChatResult, CostExhausted
from harness.kb import KB
from harness.loop import run
from harness.tools import ToolExecutor
from helpers import _cfg, _ctx, _fake_submitter


class ScriptedGateway:
    """Returns queued ChatResults; raises CostExhausted when drained (the run ends)."""

    def __init__(self, script):
        self.script = list(script)
        self.total_tokens = 0

    def chat(self, model, messages, *, tools=None, now, **kw):
        if not self.script:
            raise CostExhausted("script drained")
        return self.script.pop(0)


def _res(content=None, tool_calls=None):
    return ChatResult(content=content, tool_calls=tool_calls or [], finish_reason="stop", total_tokens=1)


def _shell_call(command, cid="c1"):
    import json
    return [{"id": cid, "type": "function",
             "function": {"name": "shell", "arguments": json.dumps({"command": command})}}]


def test_loop_executes_a_tool_call_then_ends_on_cost():
    gw = ScriptedGateway([_res(tool_calls=_shell_call("echo hi"))])
    res = run(_ctx(), _cfg(), gateway=gw, submitter=_fake_submitter(), now=lambda: 0.0)
    assert res.reason == "cost_exhausted"
    assert res.turns == 1


def test_loop_captures_flag_from_tool_output():
    def fake_runner(args, **kw):
        return subprocess.CompletedProcess(args, 0, stdout="leaked: destrier{root_1}", stderr="")

    sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), KB(), sub, _cfg(), runner=fake_runner)
    gw = ScriptedGateway([_res(tool_calls=_shell_call("cat /flag"))])
    res = run(_ctx(), _cfg(), gateway=gw, submitter=sub, executor=ex, now=lambda: 0.0)
    assert res.flags_captured == 1


def test_loop_captures_flag_from_assistant_text():
    sub = _fake_submitter()
    gw = ScriptedGateway([_res(content="I found destrier{web_2} in the response")])
    res = run(_ctx(), _cfg(), gateway=gw, submitter=sub, now=lambda: 0.0)
    assert "destrier{web_2}" in sub.captured


def test_loop_ends_on_deadline_without_turn_cap():
    # a generous script; the clock jumps past the deadline after the first turn
    gw = ScriptedGateway([_res(content="thinking")] * 50)
    times = iter([0.0, 10_000.0])
    res = run(_ctx(), _cfg(), gateway=gw, submitter=_fake_submitter(), now=lambda: next(times))
    assert res.reason == "deadline"
    assert res.turns == 1  # not capped by a turn count; ended purely on time


def test_execute_tool_calls_parallel_safe_and_ordered():
    from harness.kb import KB
    from harness.loop import execute_tool_calls
    from harness.tools import ToolExecutor

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, stdout=f"out:{argv[-1]}", stderr="")

    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg(), runner=runner)
    calls = [
        {"id": "a", "type": "function", "function": {"name": "shell", "arguments": '{"command":"one"}'}},
        {"id": "b", "type": "function", "function": {"name": "shell", "arguments": '{"command":"two"}'}},
        {"id": "c", "type": "function",
         "function": {"name": "record_finding", "arguments": '{"host":"h","cls":"x","status":"suspected"}'}},
    ]
    out = execute_tool_calls(calls, ex, cap=3)
    assert [tc["id"] for tc, _ in out] == ["a", "b", "c"]   # order preserved
    assert "one" in out[0][1] and "two" in out[1][1]        # both parallel-safe ran
    assert ex.kb.findings and ex.kb.findings[0].cls == "x"  # serial stateful tool ran


def test_maybe_triage_condenses_over_threshold_and_preserves_flag_scan():
    from harness.loop import _maybe_triage
    from harness.config import Config
    from harness.gateway import ChatResult
    from helpers import _ctx

    class _GW:
        def __init__(self): self.total_tokens = 0; self.calls = 0
        def chat(self, model, messages, *, tools=None, now, **kw):
            self.calls += 1
            return ChatResult(content="CONDENSED: port 80 open; cred admin:admin",
                              tool_calls=[], finish_reason="stop", total_tokens=1)

    cfg = Config(models={}, prompts={}, strategy={"triage_over_bytes": 50}, sampling={}, tools={})
    gw = _GW()
    big = "noise " * 100
    out = _maybe_triage(big, "shell", gw, cfg, _ctx(), now=lambda: 0.0)
    assert "CONDENSED" in out and gw.calls == 1
    out2 = _maybe_triage("tiny", "shell", gw, cfg, _ctx(), now=lambda: 0.0)
    assert out2 == "tiny" and gw.calls == 1


def test_maybe_triage_falls_back_to_raw_on_gateway_error():
    from harness.loop import _maybe_triage
    from harness.config import Config
    from harness.gateway import GatewayError
    from helpers import _ctx

    class _BadGW:
        total_tokens = 0
        def chat(self, *a, **k): raise GatewayError("boom")

    cfg = Config(models={}, prompts={}, strategy={"triage_over_bytes": 10}, sampling={}, tools={})
    big = "x" * 40
    out = _maybe_triage(big, "shell", _BadGW(), cfg, _ctx(), now=lambda: 0.0)
    assert out == big


def test_maybe_triage_off_by_default():
    from harness.loop import _maybe_triage
    from harness.config import Config
    from helpers import _ctx
    cfg = Config(models={}, prompts={}, strategy={}, sampling={}, tools={})
    big = "x" * 10000
    assert _maybe_triage(big, "shell", None, cfg, _ctx(), now=lambda: 0.0) == big


def test_history_cut_index_marks_the_dropped_slice():
    from harness.loop import _history_cut_index
    hist = []
    for i in range(6):
        hist += [{"role": "assistant", "content": f"a{i}",
                  "tool_calls": [{"id": f"c{i}", "type": "function",
                                  "function": {"name": "shell", "arguments": "{}"}}]},
                 {"role": "tool", "tool_call_id": f"c{i}", "content": f"o{i}"}]
    assert _history_cut_index(hist, 2) == 8
    assert _history_cut_index(hist, 0) == 0
    assert _history_cut_index(hist, 10) == 0


def test_loop_summarizes_dropped_turns_into_progress_log():
    from harness.loop import run
    from harness.config import Config
    from harness.gateway import ChatResult, CostExhausted
    from harness.kb import KB
    from harness.tools import ToolExecutor
    from helpers import _ctx, _fake_submitter

    class _GW:
        def __init__(self, orch_turns):
            self.orch_turns = orch_turns; self.total_tokens = 0
        def chat(self, model, messages, *, tools=None, now, **kw):
            sysmsg = messages[0]["content"] if messages else ""
            if "Compress this penetration-test transcript" in sysmsg:
                return ChatResult(content="SUMMARY: ran three shell probes; nothing new.",
                                  tool_calls=[], finish_reason="stop", total_tokens=1)
            if self.orch_turns <= 0:
                raise CostExhausted("done")
            self.orch_turns -= 1
            call = [{"id": "c", "type": "function",
                     "function": {"name": "shell", "arguments": '{"command": "true"}'}}]
            return ChatResult(content=None, tool_calls=call, finish_reason="tool_calls", total_tokens=1)

    kb = KB()
    cfg = Config(models={}, prompts={},
                 strategy={"max_history_turns": 2, "summarize_trimmed": True},
                 sampling={}, tools={})

    class _Runner:
        def __call__(self, argv, capture_output, text, timeout):
            import subprocess
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg, runner=_Runner())
    run(_ctx(), cfg, gateway=_GW(orch_turns=5), submitter=_fake_submitter(),
        kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.progress_log and "SUMMARY" in kb.progress_log


# --- context-aware trimming (2026-09-12): compact on the token window, not a turn count ---

def test_estimate_tokens_scales_with_content():
    from harness.loop import _estimate_tokens
    short = [{"role": "user", "content": "hi"}]
    long = [{"role": "user", "content": "x" * 4000}]
    assert _estimate_tokens(short) < _estimate_tokens(long)
    assert _estimate_tokens(long) > 500          # ~4000 chars -> hundreds of tokens
    # tool_calls payload is counted too, not just content
    with_tc = [{"role": "assistant", "content": "", "tool_calls": [
        {"id": "c", "type": "function", "function": {"name": "shell", "arguments": "x" * 2000}}]}]
    assert _estimate_tokens(with_tc) > 200


def test_history_cut_by_tokens_keeps_all_when_under_budget():
    from harness.loop import _history_cut_index_by_tokens
    hist = [{"role": "assistant", "content": "a"}, {"role": "tool", "tool_call_id": "c", "content": "o"}] * 3
    cut = _history_cut_index_by_tokens(
        hist, budget_tokens=1_000_000, fraction=0.65, overhead_tokens=0, min_keep_turns=2)
    assert cut == 0


def test_history_cut_by_tokens_drops_oldest_when_over_budget():
    from harness.loop import _history_cut_index_by_tokens
    hist = []
    for i in range(10):
        hist += [{"role": "assistant", "content": "A" * 1000},
                 {"role": "tool", "tool_call_id": f"c{i}", "content": "O" * 1000}]
    # tiny budget -> must drop oldest; cut lands on an assistant boundary and keeps recent turns
    cut = _history_cut_index_by_tokens(
        hist, budget_tokens=4000, fraction=0.65, overhead_tokens=0, min_keep_turns=2)
    assert cut > 0
    assert hist[cut]["role"] == "assistant"          # cut on assistant boundary (API pairing)
    assert cut < len(hist)                            # something is kept


def test_history_cut_by_tokens_respects_min_keep():
    from harness.loop import _history_cut_index_by_tokens
    hist = []
    for i in range(8):
        hist += [{"role": "assistant", "content": "A" * 5000},
                 {"role": "tool", "tool_call_id": f"c{i}", "content": "O" * 5000}]
    # budget so small even one turn overflows: must still keep at least min_keep_turns assistant turns
    cut = _history_cut_index_by_tokens(
        hist, budget_tokens=100, fraction=0.65, overhead_tokens=0, min_keep_turns=3)
    kept_assistants = sum(1 for m in hist[cut:] if m["role"] == "assistant")
    assert kept_assistants == 3


def _small_history(n_turns: int):
    hist = []
    for i in range(n_turns):
        hist += [{"role": "assistant", "content": "A"},
                 {"role": "tool", "tool_call_id": f"c{i}", "content": "o"}]
    return hist


def test_compaction_cut_turn_cap_bounds_even_with_huge_budget():
    # THE REGRESSION GUARD: a large token budget must NOT disable the turn cap. With a
    # huge budget (token path never trims) the transcript must still be bounded to
    # max_turns — otherwise a big-window model carries its entire history and drowns.
    from harness.loop import _compaction_cut_index, _history_cut_index
    hist = _small_history(10)
    cut = _compaction_cut_index(
        hist, max_turns=2, budget_tokens=1_000_000, fraction=0.65,
        overhead_tokens=0, min_keep_turns=6)
    assert cut == _history_cut_index(hist, 2) > 0   # turn cap wins; history is bounded


def test_compaction_cut_token_wins_when_tighter_than_turn_cap():
    # A tiny budget (big dumps) must trim EARLIER than the turn cap allows.
    from harness.loop import _compaction_cut_index, _history_cut_index
    hist = []
    for i in range(10):
        hist += [{"role": "assistant", "content": "A" * 4000},
                 {"role": "tool", "tool_call_id": f"c{i}", "content": "O" * 4000}]
    cut = _compaction_cut_index(
        hist, max_turns=40, budget_tokens=2000, fraction=0.65,
        overhead_tokens=0, min_keep_turns=2)
    assert cut > _history_cut_index(hist, 40)   # token budget is the tighter bound


def test_compaction_cut_zero_when_neither_bound_set():
    from harness.loop import _compaction_cut_index
    hist = _small_history(10)
    assert _compaction_cut_index(
        hist, max_turns=0, budget_tokens=0, fraction=0.65,
        overhead_tokens=0, min_keep_turns=6) == 0


def test_estimate_tokens_is_message_chars_times_per_char():
    # locks the refactor: _estimate_tokens == chars * ratio, so calibrating the ratio
    # calibrates every trim decision.
    from harness.loop import _estimate_tokens, _message_chars
    msgs = [{"role": "user", "content": "hello world"},
            {"role": "assistant", "tool_calls": [{"id": "c", "type": "function"}]}]
    assert _estimate_tokens(msgs, per_char=0.3) == int(_message_chars(msgs) * 0.3)


def test_calibrated_per_char_only_ratchets_up_and_clamps():
    # THE SAFETY VALVE: the char->token ratio is corrected from the model's REAL
    # prompt_tokens, but it may only ever INCREASE (trim more), never decrease — so a
    # dense tokenizer can never cause under-trimming, and it physically cannot recreate
    # the unbounded-growth regression. Clamped to a sane ceiling so one spike can't
    # over-trim forever.
    from harness.loop import _calibrated_per_char, _TOKENS_PER_CHAR, _TOKENS_PER_CHAR_MAX
    # observed 0.40 > default -> ratchets up to 0.40
    assert _calibrated_per_char(_TOKENS_PER_CHAR, real_tokens=400, chars_sent=1000) == 0.40
    # observed lower than current -> stays (never lowers = safe direction)
    assert _calibrated_per_char(0.40, real_tokens=100, chars_sent=1000) == 0.40
    # never below the floor
    assert _calibrated_per_char(_TOKENS_PER_CHAR, real_tokens=50, chars_sent=1000) == _TOKENS_PER_CHAR
    # a spike is clamped to the ceiling
    assert _calibrated_per_char(_TOKENS_PER_CHAR, real_tokens=9000, chars_sent=1000) == _TOKENS_PER_CHAR_MAX
    # no measurement -> unchanged
    assert _calibrated_per_char(0.33, real_tokens=0, chars_sent=1000) == 0.33
    assert _calibrated_per_char(0.33, real_tokens=100, chars_sent=0) == 0.33


def test_maybe_triage_exempts_disassembly_and_hexdump():
    from harness.loop import _maybe_triage
    from harness.config import Config
    from harness.gateway import ChatResult
    from helpers import _ctx

    class _GW:
        def __init__(self): self.total_tokens = 0; self.calls = 0
        def chat(self, model, messages, *, tools=None, now, **kw):
            self.calls += 1
            return ChatResult(content="CONDENSED", tool_calls=[], finish_reason="stop", total_tokens=1)

    cfg = Config(models={}, prompts={}, strategy={"triage_over_bytes": 50}, sampling={}, tools={})
    disasm = "\n".join(f"  40{i:04x}:\t55 48 89 e5   \tpush rbp" for i in range(40))
    hexdump = "\n".join(f"{i*16:08x}: 7f45 4c46 0201 0100 0000 0000  .ELF......" for i in range(40))
    prose = "noise " * 200

    gw = _GW()
    assert _maybe_triage(disasm, "shell", gw, cfg, _ctx(), now=lambda: 0.0) == disasm   # verbatim
    assert _maybe_triage(hexdump, "shell", gw, cfg, _ctx(), now=lambda: 0.0) == hexdump  # verbatim
    assert gw.calls == 0                                                                 # never summarized
    out = _maybe_triage(prose, "shell", gw, cfg, _ctx(), now=lambda: 0.0)
    assert "CONDENSED" in out and gw.calls == 1                                          # prose IS condensed


def test_summarize_dropped_respects_configured_cap():
    from harness.loop import _summarize_dropped
    from harness.config import Config
    from harness.gateway import ChatResult
    from helpers import _ctx

    class _GW:
        total_tokens = 0
        def chat(self, model, messages, *, tools=None, now, **kw):
            return ChatResult(content="S" * 9000, tool_calls=[], finish_reason="stop", total_tokens=1)

    dropped = [{"role": "assistant", "content": "did stuff"}]
    cfg = Config(models={}, prompts={}, strategy={}, sampling={}, tools={})
    out = _summarize_dropped(dropped, "", _GW(), cfg, _ctx(), now=lambda: 0.0, max_chars=6000)
    assert len(out) == 6000


def test_loop_turn_cap_bounds_even_with_large_budget():
    """REGRESSION GUARD (a regression run, glm-5.3 1.3M window): a large context_token_budget
    must NOT disable the turn cap. Previously the token path SUPERSEDED max_history_turns,
    so on a big-window model the transcript never hit the token threshold and grew
    unbounded (~300 messages) — the agent drowned and never captured the flag. With both
    set, the turn cap still bounds the history, so trimming fires and the dropped turns
    fold into the progress log."""
    from harness.loop import run
    from harness.config import Config
    from harness.gateway import ChatResult, CostExhausted
    from harness.kb import KB
    from harness.tools import ToolExecutor
    from helpers import _ctx, _fake_submitter

    class _GW:
        def __init__(self, n): self.n = n; self.total_tokens = 0
        def chat(self, model, messages, *, tools=None, now, **kw):
            sysmsg = messages[0]["content"] if messages else ""
            if "Compress this penetration-test transcript" in sysmsg:
                return ChatResult(content="SUMMARY: ran three shell probes; nothing new.",
                                  tool_calls=[], finish_reason="stop", total_tokens=1)
            if self.n <= 0:
                raise CostExhausted("done")
            self.n -= 1
            call = [{"id": "c", "type": "function",
                     "function": {"name": "shell", "arguments": '{"command": "true"}'}}]
            return ChatResult(content=None, tool_calls=call, finish_reason="tool_calls", total_tokens=1)

    kb = KB()
    cfg = Config(models={}, prompts={},
                 strategy={"max_history_turns": 2, "summarize_trimmed": True,
                           "context_token_budget": 1_000_000, "compact_at_context_fraction": 0.65},
                 sampling={}, tools={})

    class _Runner:
        def __call__(self, argv, capture_output, text, timeout):
            import subprocess
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg, runner=_Runner())
    run(_ctx(), cfg, gateway=_GW(6), submitter=_fake_submitter(), kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.progress_log and "SUMMARY" in kb.progress_log   # turn cap bounded it; trim fired


def test_loop_calibrates_per_char_from_prompt_tokens_and_still_trims():
    """The calibration feedback path runs in the loop: a reported prompt_tokens updates
    the char->token ratio each turn, and the run still trims (token FOCUS budget primary)
    and completes cleanly rather than erroring."""
    from harness.loop import run
    from harness.config import Config
    from harness.gateway import ChatResult, CostExhausted
    from harness.kb import KB
    from harness.tools import ToolExecutor
    from helpers import _ctx, _fake_submitter

    class _GW:
        def __init__(self, n): self.n = n; self.total_tokens = 0
        def chat(self, model, messages, *, tools=None, now, **kw):
            sysmsg = messages[0]["content"] if messages else ""
            if "Compress this penetration-test transcript" in sysmsg:
                return ChatResult(content="SUMMARY: probed; nothing new.",
                                  tool_calls=[], finish_reason="stop", total_tokens=1)
            if self.n <= 0:
                raise CostExhausted("done")
            self.n -= 1
            call = [{"id": "c", "type": "function",
                     "function": {"name": "shell", "arguments": '{"command": "true"}'}}]
            # report a real prompt size so the calibration path executes
            return ChatResult(content=None, tool_calls=call, finish_reason="tool_calls",
                              total_tokens=9000, prompt_tokens=9000)

    kb = KB()
    cfg = Config(models={}, prompts={},
                 strategy={"max_history_turns": 2, "summarize_trimmed": True,
                           "context_token_budget": 32000, "compact_at_context_fraction": 0.75},
                 sampling={}, tools={})

    class _Runner:
        def __call__(self, argv, capture_output, text, timeout):
            import subprocess
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg, runner=_Runner())
    run(_ctx(), cfg, gateway=_GW(6), submitter=_fake_submitter(), kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.progress_log and "SUMMARY" in kb.progress_log   # ran clean and trimmed


def test_loop_rides_out_a_brownout_then_continues():
    """A provider brownout (UpstreamUnavailable) must NOT end a run with budget + time to
    spare. The loop cools down and re-enters; once the provider recovers it runs on to its
    normal end. Regression: a regression run — a glm-5.3 brownout ended a run at 46% budget."""
    from harness.gateway import UpstreamUnavailable

    class _BrownoutThenRecover:
        def __init__(self, fail_times):
            self.fail_times = fail_times
            self.calls = 0
            self.total_tokens = 0

        def chat(self, model, messages, *, tools=None, now, **kw):
            self.calls += 1
            if self.calls <= self.fail_times:
                raise UpstreamUnavailable("brownout")
            if self.calls <= self.fail_times + 2:
                return _res(content="back to work")
            raise CostExhausted("done")

    slept = []
    gw = _BrownoutThenRecover(fail_times=2)
    res = run(_ctx(), _cfg(), gateway=gw, submitter=_fake_submitter(),
              now=lambda: 0.0, sleeper=slept.append)
    assert res.reason == "cost_exhausted"   # recovered and ended normally, not on the brownout
    assert res.turns == 2                    # the two good turns after the brownout cleared
    assert len(slept) == 2                   # one cooldown per brownout, then it continued


def test_loop_gives_up_after_a_persistent_brownout():
    """A brownout that never clears cannot spin forever: after a bounded number of
    consecutive cooldowns the loop gives up with the real reason (upstream_unavailable),
    which the trace can then surface instead of a healthy-looking 'agent-exited'."""
    from harness.gateway import UpstreamUnavailable
    from harness.loop import _MAX_BROWNOUT_COOLDOWNS

    class _AlwaysBrownout:
        def __init__(self):
            self.calls = 0
            self.total_tokens = 0

        def chat(self, model, messages, *, tools=None, now, **kw):
            self.calls += 1
            raise UpstreamUnavailable("still down")

    slept = []
    gw = _AlwaysBrownout()
    res = run(_ctx(), _cfg(), gateway=gw, submitter=_fake_submitter(),
              now=lambda: 0.0, sleeper=slept.append)
    assert res.reason == "upstream_unavailable"
    assert len(slept) == _MAX_BROWNOUT_COOLDOWNS          # cooled down the cap, then stopped
    assert gw.calls == _MAX_BROWNOUT_COOLDOWNS + 1        # the (cap+1)th brownout tripped the give-up


def test_loop_brownout_streak_resets_after_a_good_call():
    """The give-up bound is on CONSECUTIVE brownouts — a good call in between resets it, so a
    long run with occasional hiccups is never falsely ended."""
    from harness.gateway import UpstreamUnavailable

    class _Flaky:
        def __init__(self, pattern):
            self.pattern = list(pattern)
            self.i = 0
            self.total_tokens = 0

        def chat(self, model, messages, *, tools=None, now, **kw):
            if self.i >= len(self.pattern):
                raise CostExhausted("end")
            step = self.pattern[self.i]
            self.i += 1
            if step == "b":
                raise UpstreamUnavailable("hiccup")
            return _res(content="ok")

    slept = []
    # two runs of 3 brownouts, each cleared by a good call — never reaches the cap of 4.
    gw = _Flaky(["b", "b", "b", "g", "b", "b", "b", "g"])
    res = run(_ctx(), _cfg(), gateway=gw, submitter=_fake_submitter(),
              now=lambda: 0.0, sleeper=slept.append)
    assert res.reason == "cost_exhausted"   # streak reset by the good calls; never gave up
    assert res.turns == 2                    # the two good turns
    assert len(slept) == 6                   # six cooldowns, none crossing the consecutive cap


# --- RE static-churn -> emulate nudge -------------------------------------------------
# When the agent hand-disassembles the same target for several turns with no new findings,
# the harness forces the switch to dynamic emulation (the baked unicorn helper). This is
# the structural cure for the observed "says 'use unicorn', keeps running objdump" thrash.

class RecordingGateway:
    """Like ScriptedGateway but records every message list it is sent, so a test can
    assert that a nudge was injected into the transcript on a later turn."""

    def __init__(self, script):
        self.script = list(script)
        self.total_tokens = 0
        self.calls = []

    def chat(self, model, messages, *, tools=None, now, **kw):
        self.calls.append(messages)
        if not self.script:
            raise CostExhausted("script drained")
        return self.script.pop(0)


def _nudged(gw, needle):
    return any(any(needle in (m.get("content") or "") for m in msgs) for msgs in gw.calls)


def _re_cfg(**strategy):
    from harness.config import Config
    return Config(models={}, prompts={}, strategy=strategy, sampling={}, tools={})


def _quiet_runner(args, **kw):
    return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


def test_re_static_churn_triggers_the_emulate_nudge():
    cfg = _re_cfg(re_emulate_nudge=True, re_emulate_nudge_after=3)
    sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), KB(), sub, cfg, runner=_quiet_runner)
    gw = RecordingGateway([_res(tool_calls=_shell_call("objdump -d /workspace/example-service.bin"))] * 6)
    run(_ctx(), cfg, gateway=gw, submitter=sub, executor=ex, now=lambda: 0.0)
    assert _nudged(gw, "hand-tracing")   # the emulate nudge fired after the churn threshold


def test_emulate_usage_resets_the_churn_streak():
    cfg = _re_cfg(re_emulate_nudge=True, re_emulate_nudge_after=3)
    sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), KB(), sub, cfg, runner=_quiet_runner)
    # two static passes, an emulation (resets), two more static passes: never 3 in a row.
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("objdump -d bin", "a")),
        _res(tool_calls=_shell_call("objdump -d bin", "b")),
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --start 0x1189 --len 32", "c")),
        _res(tool_calls=_shell_call("objdump -d bin", "d")),
        _res(tool_calls=_shell_call("objdump -d bin", "e")),
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, executor=ex, now=lambda: 0.0)
    assert not _nudged(gw, "hand-tracing")


def test_no_emulate_nudge_when_flag_off():
    cfg = _re_cfg()   # re_emulate_nudge absent -> default off
    sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), KB(), sub, cfg, runner=_quiet_runner)
    gw = RecordingGateway([_res(tool_calls=_shell_call("objdump -d bin"))] * 6)
    run(_ctx(), cfg, gateway=gw, submitter=sub, executor=ex, now=lambda: 0.0)
    assert not _nudged(gw, "hand-tracing")


def test_a_real_finding_resets_the_churn_streak():
    # Progress (a new KB fact), not only emulation, breaks a static-RE streak: the agent
    # that keeps learning while it reads is not thrashing.
    import json
    cfg = _re_cfg(re_emulate_nudge=True, re_emulate_nudge_after=3)
    sub = _fake_submitter()
    kb = KB()  # shared with the executor so a recorded finding is progress the loop sees
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_quiet_runner)

    def _finding_call():
        return [{"id": "f", "type": "function", "function": {
            "name": "record_finding",
            "arguments": json.dumps({"host": "box", "cls": "lead", "status": "suspected"})}}]

    gw = RecordingGateway([
        _res(tool_calls=_shell_call("objdump -d bin", "a")),
        _res(tool_calls=_shell_call("objdump -d bin", "b")),
        _res(tool_calls=_finding_call()),                       # progress -> resets streak
        _res(tool_calls=_shell_call("objdump -d bin", "d")),
        _res(tool_calls=_shell_call("objdump -d bin", "e")),
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert not _nudged(gw, "hand-tracing")


def test_notes_or_progress_churn_does_not_defeat_the_emulate_nudge():
    # Regression for a regression run: the emulate nudge NEVER fired across 93 turns despite
    # ~15 hand-disassembly turns. Cause: the model's constant self-recaps forced frequent
    # history trims that rewrote kb.progress_log (and it rewrote kb.notes), both in the KB
    # fingerprint — so `made_progress` was true between static turns and reset the RE-static
    # streak before it reached the threshold. Here we churn kb.notes (via update_notes)
    # between objdump turns, WITHOUT any new discovery. The streak must survive the churn
    # and fire the nudge — because it now resets only on a real discovery or an emulation.
    import json
    cfg = _re_cfg(re_emulate_nudge=True, re_emulate_nudge_after=3, planning=True)
    sub = _fake_submitter()
    kb = KB()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_quiet_runner)

    def _notes_call(txt):
        return [{"id": "n", "type": "function", "function": {
            "name": "update_notes", "arguments": json.dumps({"notes": txt})}}]

    gw = RecordingGateway([
        _res(tool_calls=_shell_call("cd /workspace && objdump -d bin", "a")),
        _res(tool_calls=_notes_call("# Compressed Summary v1")),   # churns fingerprint, not a discovery
        _res(tool_calls=_shell_call("cd /workspace && objdump -d bin", "b")),
        _res(tool_calls=_notes_call("# Compressed Summary v2")),
        _res(tool_calls=_shell_call("cd /workspace && objdump -d bin", "c")),
        _res(tool_calls=_notes_call("# Compressed Summary v3")),
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.notes == "# Compressed Summary v3"      # the churn really happened
    assert _nudged(gw, "hand-tracing")                # yet the nudge still fired


# --- Self-recap fold ------------------------------------------------------------------
# The model burns whole turns re-emitting a "# Compressed Summary" of its own state (run
# regression-case: 18 such turns in one run). Worse, that recap RE-PROMOTES stale conclusions the
# trim keeps destroying — in regression-case it re-cemented a dead "construct a static frame"
# theory and dropped a tool-confirmed double-fetch race verdict. fold_self_recaps folds a
# pure-text recap turn into the durable PROGRESS LOG and stubs it in the transcript, so the
# state stays visible without the model paying to rewrite it every few turns.

def test_is_self_recap_detects_pure_text_recap_but_not_an_action_turn():
    from harness.loop import _is_self_recap
    recap = {"role": "assistant", "content": (
        "## Updated Transcript — Compressed Summary\n\n## Confirmed Facts\n"
        "- Foothold: dev shell\n- Protocol: 16-byte frames\n\n## Already Tried & Failed\n"
        + "- detail line preserving prior reasoning\n" * 100)}
    assert _is_self_recap(recap, 1200)
    # a reasoning + tool-call turn is an ACTION (it has tool_calls) — never folded, even if long
    action = {"role": "assistant", "content": "Let me disassemble it. " * 100,
              "tool_calls": _shell_call("objdump -d bin")}
    assert not _is_self_recap(action, 1200)
    # a short assistant message is not a recap
    assert not _is_self_recap({"role": "assistant", "content": "ok, trying that next."}, 1200)


def test_loop_folds_a_self_recap_into_progress_log_and_stubs_the_transcript():
    cfg = _re_cfg(fold_self_recaps=True)
    kb = KB()
    sub = _fake_submitter()
    big_recap = ("## Compressed Summary\n\n## Confirmed Facts\n"
                 "- reply constant f4836d2e is the reject message\n"
                 + "- filler detail line to make this a large recap turn\n" * 60)
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_quiet_runner)
    gw = RecordingGateway([_res(content=big_recap)])   # one pure-text recap turn, then drained
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    # the recap's reasoning survives in the durable PROGRESS LOG (re-shown every turn)...
    assert "f4836d2e is the reject message" in kb.progress_log
    # ...but the bulky prose is gone from the transcript, replaced by a short stub.
    sent_assistant = [m for m in gw.calls[-1] if m.get("role") == "assistant"]
    assert len(sent_assistant) == 1
    assert "f4836d2e" not in (sent_assistant[0].get("content") or "")
    assert "fold" in (sent_assistant[0].get("content") or "").lower()


def test_no_self_recap_fold_when_flag_off():
    cfg = _re_cfg()   # fold_self_recaps absent -> default off
    kb = KB()
    sub = _fake_submitter()
    big_recap = ("## Compressed Summary\n\n## Confirmed Facts\n"
                 "- reply constant f4836d2e is the reject message\n"
                 + "- filler\n" * 60)
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_quiet_runner)
    gw = RecordingGateway([_res(content=big_recap)])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.progress_log == ""                        # nothing folded
    sent_assistant = [m for m in gw.calls[-1] if m.get("role") == "assistant"]
    assert "f4836d2e" in (sent_assistant[0].get("content") or "")   # recap left intact


# --- Race lock-in ---------------------------------------------------------------------
# re_emulate can DETERMINISTICALLY confirm the root gate is a double-fetch (check-then-
# commit) race. In a regression run that verdict reached the model ~5x, but noisy broken-local-
# lab evidence argued it away and the model reverted to constructing a static frame (which
# can NEVER pass). race_lock_in captures the verdict from tool output and pins it in the
# SITUATION every turn; race_build_nudge pushes the model to WRITE the concurrent exploit
# instead of hand-tracing (a regression run wrote zero memfd/MAP_SHARED code).

def _race_runner(args, **kw):
    """A shell runner that emulates `re_emulate ... --solve` printing a double-fetch RACE
    verdict on stdout (generic placeholder field/values — no box constants)."""
    from harness.re_emulate import race_diagnosis
    joined = " ".join(args) if isinstance(args, (list, tuple)) else str(args)
    out = ""
    if "re_emulate" in joined or "--solve" in joined:
        out = "accepted: False\nsolve: " + race_diagnosis([(0x08, [0x11112222, 0x33334444])])
    return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")


def test_extract_race_verdict_captures_the_tool_block():
    from harness.loop import _extract_race_verdict
    from harness.re_emulate import race_diagnosis
    text = "accepted: False\nsolve: " + race_diagnosis([(0x08, [0x11112222, 0x33334444])]) + "\n(done)"
    got = _extract_race_verdict(text)
    assert got and "RACE (double-fetch / TOCTOU)" in got
    assert "race-condition-toctou" in got            # captured through the actionable tail
    assert _extract_race_verdict("nothing race-y here") is None


def test_loop_pins_a_race_verdict_from_tool_output_into_the_digest():
    cfg = _re_cfg(race_lock_in=True)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_race_runner)
    gw = RecordingGateway([_res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve"))])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert "RACE (double-fetch / TOCTOU)" in kb.race_verdict
    assert _nudged(gw, "CONFIRMED BY EMULATOR")      # pinned into the SITUATION the next turn


def test_no_race_pin_when_flag_off():
    cfg = _re_cfg()   # race_lock_in absent -> default off
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_race_runner)
    gw = RecordingGateway([_res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve"))])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.race_verdict == ""


def test_race_build_nudge_fires_when_agent_wont_build_after_a_confirmed_race():
    cfg = _re_cfg(race_lock_in=True, race_build_nudge=True, race_build_nudge_after=2)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_race_runner)
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve", "a")),  # pins verdict
        _res(tool_calls=_shell_call("objdump -d bin", "b")),                              # static, no build
        _res(tool_calls=_shell_call("python3 -c 'struct.pack(frame)'", "c")),             # frame-construct, no build
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.race_verdict
    assert _nudged(gw, "NOT building the concurrent exploit")


def test_race_build_nudge_resets_when_the_agent_builds_the_exploit():
    cfg = _re_cfg(race_lock_in=True, race_build_nudge=True, race_build_nudge_after=2)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_race_runner)
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve", "a")),      # pins verdict
        _res(tool_calls=_shell_call("python3 -c 'os.memfd_create(x); mmap MAP_SHARED'", "b")), # BUILDING -> reset
        _res(tool_calls=_shell_call("objdump -d bin", "c")),                                  # one static, streak=1
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.race_verdict
    assert not _nudged(gw, "NOT building the concurrent exploit")


def test_race_build_nudge_off_by_default():
    cfg = _re_cfg(race_lock_in=True)   # lock-in on, but nudge absent -> off
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_race_runner)
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve", "a")),
        _res(tool_calls=_shell_call("objdump -d bin", "b")),
        _res(tool_calls=_shell_call("objdump -d bin", "c")),
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert not _nudged(gw, "NOT building the concurrent exploit")


# --- Race lock-in hardening (from live a regression run) ----------------------------------
# regression-case exposed two flaws in race_lock_in: (1) _extract_race_verdict pinned the SKILL's
# explainer text (which merely contains the phrase) instead of the emulator's real verdict, so
# the pin carried no concrete values; (2) the model ran `win_race --selftest` 30x — a rehearsal,
# not an attack — and that reset the build-nudge streak, so the nudge never pushed it to FIRE at
# the target. It reversed forever and never ran win_race against the live socket.

def test_extract_race_verdict_ignores_skill_explainer_text():
    from harness.loop import _extract_race_verdict
    # what consult_skill / the prompt returns — has the phrase, but NOT the emulator's verdict
    # and no concrete values. This is exactly what regression-case wrongly pinned.
    skill_text = ("`RACE (double-fetch / TOCTOU)`** — it found ONE field compared against TWO "
                  "different constants (the validator re-reads it and demands different values, "
                  "e.g. a PREVIEW then a COMMIT mode). consult_skill 'race-condition-toctou'.")
    assert _extract_race_verdict(skill_text) is None
    # the real emulator verdict (with concrete field + BOTH values) IS captured and carries them
    from harness.re_emulate import race_diagnosis
    real = "accepted: False\nsolve: " + race_diagnosis([(0x08, [0x11112222, 0x33334444])])
    got = _extract_race_verdict(real)
    assert got and "11112222" in got and "33334444" in got


def test_race_build_nudge_fires_when_agent_only_rehearses_selftest():
    cfg = _re_cfg(race_lock_in=True, race_build_nudge=True, race_build_nudge_after=2)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_race_runner)
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve", "a")),   # pins verdict
        _res(tool_calls=_shell_call("python3 -m harness.win_race --selftest", "b")),       # rehearsal only
        _res(tool_calls=_shell_call("python3 -m harness.win_race --selftest", "c")),       # rehearsal only
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.race_verdict
    assert _nudged(gw, "NOT building the concurrent exploit")   # selftest is not firing


def test_race_build_nudge_resets_on_a_real_fire_at_the_target():
    cfg = _re_cfg(race_lock_in=True, race_build_nudge=True, race_build_nudge_after=2)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_race_runner)
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve", "a")),                    # pin
        _res(tool_calls=_shell_call("python3 -m harness.win_race --sock /run/x.sock --submit-hex aa", "b")),  # real fire -> reset
        _res(tool_calls=_shell_call("objdump -d bin", "c")),                                               # one static, streak=1
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.race_verdict
    assert not _nudged(gw, "NOT building the concurrent exploit")


# --- Static-accept-must-be-proven-live (the example validator root-cause fix) ----------------------
# re_emulate can only detect a double-fetch as a FALLBACK when a static solve FAILS on the one
# function the model aimed at. But a check-then-commit daemon's VALIDATOR statically ACCEPTS
# (PREVIEW passes) — the second read that demands COMMIT lives in the daemon's request handler,
# not the validator. So the emulator prints `accepted: True` / `solve: ACCEPTED`, the model takes
# it as a win, grinds RE, and never discovers the race (runs regression-case / regression-case / regression-case).
# prove_static_accept_live reframes a static ACCEPT the moment it happens: it is a HYPOTHESIS, not
# a win — prove it against the LIVE daemon; a live rejection of an emulator-accepted frame IS the
# double-fetch, so win it concurrently with win_race (sweep the second value). Generic; no answer.

def _accept_runner(args, **kw):
    """A shell runner that emulates `re_emulate` statically ACCEPTING a frame (the false-comfort
    a check-then-commit VALIDATOR gives) — no race verdict, generic placeholder frame."""
    joined = " ".join(args) if isinstance(args, (list, tuple)) else str(args)
    out = ""
    if "re_emulate" in joined:
        out = ("accepted: True  (emulated 40 instructions)\n"
               "solve: ACCEPTED\n  frame (16 bytes): 0102030405060708090a0b0c0d0e0f10\n")
    return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")


def test_emitted_static_accept_matches_accept_lines_not_reject_or_race():
    from harness.loop import _emitted_static_accept
    from harness.re_emulate import race_diagnosis
    assert _emitted_static_accept("accepted: True  (emulated 40 instructions)")
    assert _emitted_static_accept("solve: ACCEPTED\n  frame (16 bytes): aabb")
    assert not _emitted_static_accept("accepted: False  (emulated 40 instructions)")
    assert not _emitted_static_accept("no direct arg-compares found")
    # an output that ALSO carries the emulator's race verdict is NOT a clean static accept:
    # the race machinery owns it, the prove-live reframe must stay out of the way.
    both = "accepted: True\nsolve: " + race_diagnosis([(0x08, [0x11112222, 0x33334444])])
    assert not _emitted_static_accept(both)


def test_did_live_submit_recognizes_a_socket_submit_not_an_emulate():
    from harness.loop import _did_live_submit
    assert _did_live_submit(_shell_call("nc -U /run/example-service.sock < frame.bin"))
    assert _did_live_submit(_shell_call("python3 -c 's=socket.socket(socket.AF_UNIX); s.sendmsg([b])'"))
    assert _did_live_submit(_shell_call("python3 -m harness.win_race --sock /run/x.sock --submit-hex aa"))
    assert not _did_live_submit(_shell_call("python3 -m harness.re_emulate bin --solve"))
    assert not _did_live_submit(_shell_call("objdump -d bin"))


def test_prove_live_nudge_differs_pre_and_post_live_test_and_routes_to_win_race():
    from harness.loop import _prove_live_nudge
    pre = _prove_live_nudge(False)["content"]
    post = _prove_live_nudge(True)["content"]
    assert pre != post
    for text in (pre, post):
        assert "win_race" in text and "race-condition-toctou" in text
    assert "HYPOTHESIS" in pre                 # pre-test: reframe the false comfort
    assert "does not honor" in post            # post-test: the discrepancy IS the double-fetch


def test_prove_live_nudge_fires_the_moment_the_emulator_statically_accepts():
    cfg = _re_cfg(prove_static_accept_live=True)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_accept_runner)
    gw = RecordingGateway([_res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve"))])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert kb.race_verdict == ""               # no fabricated verdict — it stays a hypothesis
    assert _nudged(gw, "win_race")
    assert _nudged(gw, "HYPOTHESIS")


def test_prove_live_nudge_off_by_default():
    cfg = _re_cfg()   # prove_static_accept_live absent -> default off
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_accept_runner)
    gw = RecordingGateway([_res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve"))])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert not _nudged(gw, "HYPOTHESIS")


def test_prove_live_nudge_escalates_after_the_frame_is_tested_live():
    cfg = _re_cfg(prove_static_accept_live=True, prove_live_nudge_after=2)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_accept_runner)
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve", "a")),  # static accept -> seen, pre nudge
        _res(tool_calls=_shell_call("nc -U /run/example-service.sock < frame.bin", "b")),         # tested live -> escalate
        _res(tool_calls=_shell_call("objdump -d bin", "c")),
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    assert _nudged(gw, "does not honor")       # the post-live escalation fired


def test_prove_live_nudge_stops_once_the_agent_builds_the_race_exploit():
    cfg = _re_cfg(prove_static_accept_live=True, prove_live_nudge_after=2)
    kb = KB(); sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), kb, sub, cfg, runner=_accept_runner)
    gw = RecordingGateway([
        _res(tool_calls=_shell_call("python3 -m harness.re_emulate bin --solve", "a")),        # accept -> seen, pre nudge (1)
        _res(tool_calls=_shell_call("python3 -c 'os.memfd_create(x); mmap MAP_SHARED'", "b")),  # BUILDING -> stop nudging
        _res(tool_calls=_shell_call("python3 -c 'os.memfd_create(x); mmap MAP_SHARED'", "c")),  # still building
        _res(tool_calls=_shell_call("python3 -c 'os.memfd_create(x); mmap MAP_SHARED'", "d")),  # still building
    ])
    run(_ctx(), cfg, gateway=gw, submitter=sub, kb=kb, executor=ex, now=lambda: 0.0)
    # each appended nudge is a distinct message that persists in history, so count copies in the
    # final accumulated transcript (not calls-containing-it): 1 = fired once, then the build silenced it.
    last = gw.calls[-1]
    n = sum(1 for m in last if "HYPOTHESIS" in (m.get("content") or ""))
    assert n == 1        # fired once at the accept, then the build guard silenced it

import json
import subprocess

from harness.gateway import ChatResult, CostExhausted
from harness.kb import KB
from harness.subagent import run_specialist
from harness.tools import ToolExecutor, tool_specs
from helpers import _cfg, _ctx, _fake_submitter


class ScriptedGateway:
    def __init__(self, script):
        self.script = list(script)
        self.total_tokens = 0

    def chat(self, model, messages, *, tools=None, now, **kw):
        if not self.script:
            raise CostExhausted("drained")
        return self.script.pop(0)


def _res(content=None, tool_calls=None):
    return ChatResult(content=content, tool_calls=tool_calls or [], finish_reason="stop", total_tokens=1)


def _call(cid, name, **args):
    return [{"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]


def _fake_runner(args, **kw):
    return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")


def test_specialist_runs_tool_then_reports():
    kb = KB()
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), _cfg(), runner=_fake_runner)
    gw = ScriptedGateway([
        _res(tool_calls=_call("c1", "shell", command="nmap -sT box")),
        _res(tool_calls=_call("c2", "report_done", outcome="success", summary="port 80 open")),
    ])
    res = run_specialist("recon", "map the box", ctx=_ctx(), cfg=_cfg(), gateway=gw,
                         submitter=_fake_submitter(), kb=kb, executor=ex, now=lambda: 0.0)
    assert res.outcome == "success"
    assert res.turns == 2
    assert "port 80" in res.summary


def test_specialist_stalls_and_returns():
    kb = KB()
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), _cfg(), runner=_fake_runner)
    gw = ScriptedGateway([_res(content="thinking")] * 6)
    res = run_specialist("web", "exploit it", ctx=_ctx(), cfg=_cfg(), gateway=gw,
                         submitter=_fake_submitter(), kb=kb, executor=ex, now=lambda: 0.0, max_stall=2)
    assert res.outcome == "stalled"
    assert res.turns == 2  # returns on stall, not a turn cap


def test_delegate_tool_invokes_specialist():
    kb = KB()
    gw = ScriptedGateway([
        _res(tool_calls=_call("c1", "shell", command="id")),
        _res(tool_calls=_call("c2", "report_done", outcome="success", summary="rooted")),
    ])
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), _cfg(), runner=_fake_runner, gateway=gw, now=lambda: 0.0)
    out = ex.execute("delegate", {"specialist": "privesc", "goal": "get root"})
    assert "privesc" in out
    assert "success" in out
    assert "rooted" in out


def test_delegate_unknown_specialist_is_rejected():
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg(), gateway=object(), now=lambda: 0.0)
    out = ex.execute("delegate", {"specialist": "wizard", "goal": "x"})
    assert "unknown specialist" in out


def test_specs_gate_delegate_and_report_done():
    orch = {s["function"]["name"] for s in tool_specs(_cfg(), delegate=True)}
    spec = {s["function"]["name"] for s in tool_specs(_cfg(), report_done=True)}
    plain = {s["function"]["name"] for s in tool_specs(_cfg())}
    assert "delegate" in orch and "report_done" not in orch
    assert "report_done" in spec and "delegate" not in spec
    assert "delegate" not in plain and "report_done" not in plain
    # config can turn specialists off
    off = {s["function"]["name"] for s in tool_specs(_cfg(enable_specialists=False), delegate=True)}
    assert "delegate" not in off


def test_specialist_dead_end_is_recorded_in_kb_dead_ends():
    import json
    from harness.config import Config
    from harness.gateway import ChatResult
    from harness.kb import KB
    from harness.subagent import run_specialist
    from harness.tools import ToolExecutor
    from helpers import _ctx, _fake_submitter

    class _GW:
        total_tokens = 0
        def chat(self, model, messages, *, tools=None, now, **kw):
            call = [{"id": "d", "type": "function", "function": {
                "name": "report_done",
                "arguments": json.dumps({"outcome": "dead_end",
                                         "summary": "SQLi filtered, no other web vector"})}}]
            return ChatResult(content=None, tool_calls=call, finish_reason="tool_calls", total_tokens=1)

    kb = KB()
    cfg = Config(models={}, prompts={}, strategy={}, sampling={}, tools={})
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg, gateway=_GW())
    run_specialist("web", "exploit the app", ctx=_ctx(), cfg=cfg, gateway=_GW(),
                   submitter=_fake_submitter(), kb=kb, executor=ex, now=lambda: 0.0)
    assert any("web" in d and "SQLi filtered" in d for d in kb.dead_ends)

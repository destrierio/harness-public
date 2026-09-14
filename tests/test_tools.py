from harness.kb import KB
from harness.tools import ToolExecutor, tool_specs
from helpers import _cfg, _ctx, _fake_submitter


def test_shell_trims_output():
    cfg = _cfg(shell_output_limit=5, shell_timeout_seconds=5)
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), cfg)
    out = ex.execute("shell", {"command": "printf 1234567890"})
    assert out.startswith("12345")
    assert len(out) <= 128  # trimmed to the limit plus a short truncation marker


def test_shell_timeout_is_reported_not_raised():
    cfg = _cfg(shell_output_limit=8000, shell_timeout_seconds=1)
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), cfg)
    out = ex.execute("shell", {"command": "sleep 5"})
    assert "timed out" in out.lower()


def test_record_finding_lands_in_kb():
    kb = KB()
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), _cfg())
    ex.execute(
        "record_finding",
        {"host": "box", "service": "80/tcp", "cls": "lfi", "status": "confirmed",
         "evidence": "x", "next_action": "y"},
    )
    assert kb.findings and kb.findings[0].cls == "lfi"


def test_submit_flag_tool_calls_submitter():
    sub = _fake_submitter()
    ex = ToolExecutor(_ctx(), KB(), sub, _cfg())
    ex.execute("submit_flag", {"flag": "destrier{root_1}"})
    assert "destrier{root_1}" in sub.submitted


def test_unknown_tool_returns_error_string():
    ex = ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg())
    out = ex.execute("nope", {})
    assert "unknown tool" in out.lower()


def test_tool_specs_are_valid_openai_schemas():
    specs = tool_specs(_cfg())
    for s in specs:
        assert s["type"] == "function"
        assert "name" in s["function"]
        assert s["function"]["parameters"]["type"] == "object"
    names = {s["function"]["name"] for s in specs}
    assert {"shell", "submit_flag", "record_finding"} <= names


def test_update_plan_tool_offered_only_when_planning_on():
    from harness.tools import tool_specs
    from harness.config import Config
    off = Config(models={}, prompts={}, strategy={}, sampling={}, tools={})
    on = Config(models={}, prompts={}, strategy={"planning": True}, sampling={}, tools={})
    assert "update_plan" not in {s["function"]["name"] for s in tool_specs(off)}
    assert "update_plan" in {s["function"]["name"] for s in tool_specs(on)}


def test_update_plan_tool_sets_kb_plan():
    from harness.kb import KB
    from harness.tools import ToolExecutor
    from helpers import _ctx, _fake_submitter
    from harness.config import Config
    kb = KB()
    cfg = Config(models={}, prompts={}, strategy={"planning": True}, sampling={}, tools={})
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg)
    out = ex.execute("update_plan", {"steps": [{"goal": "pop the admin panel", "status": "active"}]})
    assert "1" in out
    assert kb.plan and kb.plan[0].goal == "pop the admin panel"


def test_update_notes_tool_offered_only_when_planning_on():
    from harness.tools import tool_specs
    from harness.config import Config
    off = Config(models={}, prompts={}, strategy={}, sampling={}, tools={})
    on = Config(models={}, prompts={}, strategy={"planning": True}, sampling={}, tools={})
    assert "update_notes" not in {s["function"]["name"] for s in tool_specs(off)}
    assert "update_notes" in {s["function"]["name"] for s in tool_specs(on)}


def test_update_notes_tool_sets_kb_notes():
    from harness.config import Config
    kb = KB()
    cfg = Config(models={}, prompts={}, strategy={"planning": True}, sampling={}, tools={})
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg)
    out = ex.execute("update_notes", {"notes": "0x5710 = rol9 ^ 0xa53c9e17; jmptable 0x6434"})
    assert "updated" in out.lower()
    assert kb.notes == "0x5710 = rol9 ^ 0xa53c9e17; jmptable 0x6434"


def test_update_notes_bounds_length():
    # A runaway scratchpad must not blow the context window: the tool caps what it stores.
    from harness.config import Config
    kb = KB()
    cfg = Config(models={}, prompts={}, strategy={"planning": True}, sampling={}, tools={})
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg)
    out = ex.execute("update_notes", {"notes": "A" * 20000})
    assert len(kb.notes) < 20000
    assert "truncat" in out.lower()


def test_record_access_verifies_with_id_when_enabled():
    from harness.kb import KB
    from harness.tools import ToolExecutor
    from harness.config import Config
    from helpers import _ctx, _fake_submitter

    class _Sess:
        def has(self, n): return n == "foothold"
        def send(self, n, data, timeout=2.0): return "uid=33(www-data) gid=33"
        def list(self): return ["foothold"]
        def close_all(self): pass

    kb = KB()
    cfg = Config(models={}, prompts={}, strategy={"verify_access": True}, sampling={}, tools={})
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg, sessions=_Sess())
    out = ex.execute("record_access", {"host": "box", "session": "foothold", "user": "www-data"})
    assert kb.accesses[-1].verified is True
    assert "verified" in out.lower()
    assert kb.verified_accesses() == kb.accesses


def test_record_access_unverified_when_id_absent():
    from harness.kb import KB
    from harness.tools import ToolExecutor
    from harness.config import Config
    from helpers import _ctx, _fake_submitter

    class _Sess:
        def has(self, n): return n == "foothold"
        def send(self, n, data, timeout=2.0): return "command not found"
        def list(self): return ["foothold"]
        def close_all(self): pass

    kb = KB()
    cfg = Config(models={}, prompts={}, strategy={"verify_access": True}, sampling={}, tools={})
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), cfg, sessions=_Sess())
    out = ex.execute("record_access", {"host": "box", "session": "foothold"})
    assert kb.accesses[-1].verified is False
    assert kb.verified_accesses() == []
    assert "unverified" in out.lower()


def test_record_host_tool_writes_kb():
    from harness.kb import KB
    from harness.tools import ToolExecutor
    from harness.config import Config
    from helpers import _ctx, _fake_submitter
    kb = KB()
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), Config(models={}, prompts={}, strategy={}, sampling={}, tools={}))
    ex.execute("record_host", {"address": "10.0.1.9", "hostname": "vault", "reachable_via": "foothold"})
    assert kb.hosts and kb.hosts[0].address == "10.0.1.9" and kb.hosts[0].reachable_via == "foothold"

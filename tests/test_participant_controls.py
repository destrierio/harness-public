"""Participant edits must reach model requests and preserve flag scanning."""
import copy
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from harness.config import Config
from harness.gateway import ChatResult, CostExhausted
from harness.kb import KB
from harness.loop import _maybe_triage, _summarize_dropped, run
from harness.prompts import ORCHESTRATOR_SYSTEM, SPECIALIST_SYSTEM, SUMMARIZER_SYSTEM, TRIAGE_SYSTEM
from harness.subagent import run_specialist
from harness.tools import ToolExecutor, tool_specs
from helpers import _ctx, _fake_submitter


class RecordingGateway:
    total_tokens = 0

    def __init__(self, script):
        self.script = iter(script)
        self.requests = []
        self.settings = []

    def chat(self, model, messages, **kwargs):
        self.requests.append(copy.deepcopy(messages))
        self.settings.append({"model": model, **kwargs})
        result = next(self.script, None)
        if result is None:
            raise CostExhausted("script drained")
        return result


def reply(content=None, calls=()):
    return ChatResult(content=content, tool_calls=list(calls), finish_reason="stop", total_tokens=1)


@pytest.mark.parametrize("role", [
    "orchestrator", "recon", "web", "pwn", "privesc", "triage", "summarizer",
])
@pytest.mark.parametrize("config_name", [
    "config.yaml", "config.participant.yaml", "custom",
])
def test_role_yaml_reaches_model_request(tmp_path, role, config_name):
    # Catches lost overrides, wrong role routing and dropped sampling options at
    # the model boundary. Read expected values independently of Config.load.
    if config_name == "custom":
        path = tmp_path / "config.yaml"
        path.write_text(yaml.safe_dump({
            "models": {role: "anthropic/claude-y"},
            "prompts": {f"{role}_system": f"Edited instructions for {role}."},
            "sampling": {"temperature": {role: 0.6}, "effort": {role: "medium"}},
            "strategy": {"triage_over_bytes": 1},
        }))
    else:
        path = Path(__file__).resolve().parents[1] / config_name
    data = yaml.safe_load(path.read_text())
    # A single-model event must work regardless of participant model choices.
    ctx = _ctx() if config_name == "custom" else _ctx(models="openai/gpt-x")
    cfg = Config.load(str(path), ctx)
    assert not cfg.warnings
    gateway = RecordingGateway([reply("compressed")])
    kb, submitter = KB(), _fake_submitter()
    executor = ToolExecutor(ctx, kb, submitter, cfg)
    try:
        if role == "orchestrator":
            run(ctx, cfg, gateway=gateway, submitter=submitter, kb=kb,
                executor=executor, now=lambda: 0)
        elif role == "triage":
            threshold = int(cfg.strategy.get("triage_over_bytes", 0) or 0)
            output = "x" * max(1, threshold + 1)
            condensed = _maybe_triage(output, "shell", gateway, cfg, ctx, now=lambda: 0)
            if threshold <= 0:
                assert condensed == output
                assert not gateway.requests
                return
        elif role == "summarizer":
            _summarize_dropped([{"role": "tool", "content": "earlier discovery"}],
                               "", gateway, cfg, ctx, now=lambda: 0)
        else:
            run_specialist(role, "assigned task", ctx=ctx, cfg=cfg, gateway=gateway,
                           submitter=submitter, kb=kb, executor=executor, now=lambda: 0)
    finally:
        executor.close()
    defaults = {"orchestrator": ORCHESTRATOR_SYSTEM, "triage": TRIAGE_SYSTEM,
                "summarizer": SUMMARIZER_SYSTEM, **SPECIALIST_SYSTEM}
    expected_prompt = data.get("prompts", {}).get(f"{role}_system") or defaults[role]
    assert gateway.requests[0][0]["content"].startswith(expected_prompt)
    settings = gateway.settings[0]
    assert settings["model"] == ("anthropic/claude-y" if config_name == "custom" else "openai/gpt-x")
    temperature = data.get("sampling", {}).get("temperature", {}).get(role)
    try:
        expected_temperature = float(temperature)
    except (TypeError, ValueError):
        expected_temperature = None
    effort = data.get("sampling", {}).get("effort", {}).get(role)
    assert settings["temperature"] == expected_temperature
    assert settings["effort"] == (str(effort) if effort else None)


@pytest.mark.parametrize("key,name", [
    ("enable_session", "session"), ("enable_python_exec", "python_exec"),
    ("enable_http_request", "http_request"), ("enable_reverse_shell", "reverse_shell_listener"),
    ("enable_fetch_artifact", "fetch_artifact"), ("enable_browser", "browser"),
    ("enable_specialists", "delegate"),
])
@pytest.mark.parametrize("enabled", [False, True])
def test_yaml_tool_switch_controls_available_tools(tmp_path, key, name, enabled):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"tools": {key: enabled}}))
    cfg = Config.load(str(path), _ctx())
    names = {spec["function"]["name"] for spec in tool_specs(cfg, delegate=True)}
    assert (name in names) == enabled
    assert {"shell", "submit_flag", "consult_skill"} <= names


@pytest.mark.parametrize("role,default", [("triage", TRIAGE_SYSTEM), ("summarizer", SUMMARIZER_SYSTEM)], ids=["triage", "summarizer"])
@pytest.mark.parametrize("override", ["Keep exact offsets and failed hypotheses.", "", None])
def test_compression_prompt_from_yaml_reaches_model(tmp_path, role, default, override):
    config = tmp_path / "config.yaml"
    config.write_text(json.dumps({"prompts": {f"{role}_system": override},
                                 "strategy": {"triage_over_bytes": 1}}))
    cfg = Config.load(str(config), _ctx())
    gateway = RecordingGateway([reply("compressed")])
    if role == "triage":
        _maybe_triage("verbose tool output", "shell", gateway, cfg, _ctx(), now=lambda: 0)
    else:
        _summarize_dropped([{"role": "tool", "content": "verbose tool output"}],
                           "", gateway, cfg, _ctx(), now=lambda: 0)
    assert gateway.requests[0][0] == {"role": "system", "content": override or default}


@pytest.mark.parametrize("role", ["orchestrator", "recon"])
@pytest.mark.parametrize("cap", [0, 120])
def test_output_cap_is_shared_per_turn_resets_and_scans_flags(role, cap):
    cfg = Config(models={}, prompts={}, strategy={}, sampling={},
                 tools={"max_tool_output_per_turn": cap})
    ctx, kb, submitter = _ctx(), KB(), _fake_submitter()
    outputs = {"first": "A" * 80, "second": "B" * 100 + " destrier{tail_1}",
               "third": "C" * 80}
    executed = []

    def runner(argv, **kwargs):
        executed.append(argv[-1])
        return subprocess.CompletedProcess(argv, 0, stdout=outputs[argv[-1]], stderr="")

    def call(name):
        return {"id": name, "type": "function", "function": {
            "name": "shell", "arguments": json.dumps({"command": name})}}

    gateway = RecordingGateway([reply(calls=[call("first"), call("second")]),
                                reply(calls=[call("third")])])
    executor = ToolExecutor(ctx, kb, submitter, cfg, runner=runner)
    try:
        if role == "orchestrator":
            run(ctx, cfg, gateway=gateway, submitter=submitter, kb=kb,
                executor=executor, now=lambda: 0)
        else:
            run_specialist(role, "map target", ctx=ctx, cfg=cfg, gateway=gateway,
                           submitter=submitter, kb=kb, executor=executor, now=lambda: 0)
    finally:
        executor.close()

    tool_messages = [m for m in gateway.requests[-1] if m["role"] == "tool"]
    assert [m["tool_call_id"] for m in tool_messages] == ["first", "second", "third"]
    first, second, third = [m["content"] for m in tool_messages]
    assert first == outputs["first"]
    assert third == outputs["third"]  # each new turn gets a fresh allowance
    if cap:
        assert len(first) + len(second) <= cap
        assert "truncated" in second
        assert "destrier{tail_1}" not in second
    else:
        assert second == outputs["second"]
    assert executed == ["first", "second", "third"]
    assert "destrier{tail_1}" in submitter.captured

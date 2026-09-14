"""Run the REAL harness (real Gateway, FlagSubmitter, ToolExecutor, loop) against
the offline rig — no Docker, no internet, no platform. Backs both `make run-local`
and tests/e2e/test_capture.py.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time

# Allow `python3 testrig/run_local.py` (script dir on path) as well as `-m`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.__main__ import _config_path
from harness.config import Config
from harness.flags import FlagSubmitter
from harness.gateway import Gateway
from harness.loop import RunResult, run
from harness.runtime import RunContext
from testrig.local_service import make_tcp_service
from testrig.local_target import make_target_server
from testrig.mock_gateway import make_gateway_server

FLAG = "destrier{root_1}"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(server) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def _shell_call(cid: str, command: str) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": cid, "type": "function",
            "function": {"name": "shell", "arguments": json.dumps({"command": command})},
        }],
    }


def exploit_script(target_url: str) -> list[dict]:
    return [_shell_call("c1", f"curl -s '{target_url}/?file=../flag'")]


def noexploit_script(target_url: str) -> list[dict]:
    return [
        _shell_call("c1", f"curl -s '{target_url}/'"),
        {
            "role": "assistant", "content": None,
            "tool_calls": [{
                "id": "c2", "type": "function",
                "function": {"name": "submit_flag", "arguments": json.dumps({"flag": "destrier{guess1}"})},
            }],
        },
    ]


def run_against_rig(make_script) -> RunResult:
    gw_port, target_port = _free_port(), _free_port()

    target = make_target_server(target_port, FLAG)
    _serve(target)
    target_url = f"http://127.0.0.1:{target_port}"

    gateway_server = make_gateway_server(gw_port, make_script(target_url), FLAG)
    _serve(gateway_server)

    base = f"http://127.0.0.1:{gw_port}/v1"
    env = {
        "BOXR_RUN_ID": "local",
        "BOXR_AGENT_TOKEN": "local-token",
        "BOXR_PROVIDER_BASE_URL": base,
        "BOXR_EVENT_ENDPOINT": f"http://127.0.0.1:{gw_port}/events",
        "BOXR_FLAG_ENDPOINT": f"http://127.0.0.1:{gw_port}/flag",
        "BOXR_MODEL": "test/model",
        "BOXR_MODELS": "test/model",
        "BOXR_OBJECTIVE": "read the flag",
        "BOXR_MAX_WALL_CLOCK_SEC": "60",
        "BOXR_MAX_COST_MICRO_USD": "5000000",
    }
    task = {
        "objective": "read the flag",
        "self": {"ip": "127.0.0.1"},
        "targets": [{"hostname": "127.0.0.1"}],
    }

    ctx = RunContext.from_env(env, task, now=time.monotonic())
    cfg = Config.load(_config_path(), ctx)
    gateway = Gateway(
        ctx.provider_base_url, ctx.agent_token, budget=ctx.budget,
        retry_headroom_seconds=float(cfg.strategy.get("retry_headroom_seconds", 20) or 0),
        call_timeout=float(cfg.strategy.get("model_call_timeout_seconds", 0) or 0) or None,
    )
    submitter = FlagSubmitter(ctx.flag_endpoint, ctx.event_endpoint, ctx.agent_token)

    try:
        return run(ctx, cfg, gateway=gateway, submitter=submitter)
    finally:
        target.shutdown()
        gateway_server.shutdown()


def _session_call(cid: str, action: str, **kw) -> dict:
    args = {"action": action, **kw}
    return {
        "role": "assistant", "content": None,
        "tool_calls": [{"id": cid, "type": "function",
                        "function": {"name": "session", "arguments": json.dumps(args)}}],
    }


def session_script(host: str, port: int) -> list[dict]:
    return [
        _session_call("c1", "open", name="svc", cmd=f"nc {host} {port}", timeout=1),
        _session_call("c2", "send", name="svc", data="getflag", timeout=3),
    ]


def session_noexploit_script(host: str, port: int) -> list[dict]:
    return [
        _session_call("c1", "open", name="svc", cmd=f"nc {host} {port}", timeout=1),
        _session_call("c2", "send", name="svc", data="help", timeout=3),
    ]


def run_session_rig(make_script=session_script) -> RunResult:
    gw_port, svc_port = _free_port(), _free_port()
    service = make_tcp_service(svc_port, FLAG)
    gateway_server = make_gateway_server(gw_port, make_script("127.0.0.1", svc_port), FLAG)
    _serve(gateway_server)

    base = f"http://127.0.0.1:{gw_port}/v1"
    env = {
        "BOXR_RUN_ID": "local-session",
        "BOXR_AGENT_TOKEN": "local-token",
        "BOXR_PROVIDER_BASE_URL": base,
        "BOXR_EVENT_ENDPOINT": f"http://127.0.0.1:{gw_port}/events",
        "BOXR_FLAG_ENDPOINT": f"http://127.0.0.1:{gw_port}/flag",
        "BOXR_MODEL": "test/model",
        "BOXR_MODELS": "test/model",
        "BOXR_OBJECTIVE": "get the flag from the service",
        "BOXR_MAX_WALL_CLOCK_SEC": "60",
        "BOXR_MAX_COST_MICRO_USD": "5000000",
    }
    task = {"objective": "get the flag from the service", "self": {"ip": "127.0.0.1"},
            "targets": [{"hostname": "127.0.0.1"}]}
    ctx = RunContext.from_env(env, task, now=time.monotonic())
    cfg = Config.load(_config_path(), ctx)
    gateway = Gateway(
        ctx.provider_base_url, ctx.agent_token, budget=ctx.budget,
        retry_headroom_seconds=float(cfg.strategy.get("retry_headroom_seconds", 20) or 0),
        call_timeout=float(cfg.strategy.get("model_call_timeout_seconds", 0) or 0) or None,
    )
    submitter = FlagSubmitter(ctx.flag_endpoint, ctx.event_endpoint, ctx.agent_token)
    try:
        return run(ctx, cfg, gateway=gateway, submitter=submitter)
    finally:
        service.close()
        gateway_server.shutdown()


def delegate_script(target_url: str) -> list[dict]:
    """Orchestrator delegates to the web specialist, which runs the exploit and reports."""
    return [
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "d1", "type": "function",
            "function": {"name": "delegate",
                         "arguments": json.dumps({"specialist": "web", "goal": "read the flag"})}}]},
        _shell_call("s1", f"curl -s '{target_url}/?file=../flag'"),
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "r1", "type": "function",
            "function": {"name": "report_done",
                         "arguments": json.dumps({"outcome": "success", "summary": "flag read via LFI"})}}]},
    ]


def run_delegate_rig() -> RunResult:
    gw_port, target_port = _free_port(), _free_port()
    target = make_target_server(target_port, FLAG)
    _serve(target)
    target_url = f"http://127.0.0.1:{target_port}"
    gateway_server = make_gateway_server(gw_port, delegate_script(target_url), FLAG)
    _serve(gateway_server)
    base = f"http://127.0.0.1:{gw_port}/v1"
    env = {
        "BOXR_RUN_ID": "local-delegate", "BOXR_AGENT_TOKEN": "local-token",
        "BOXR_PROVIDER_BASE_URL": base,
        "BOXR_EVENT_ENDPOINT": f"http://127.0.0.1:{gw_port}/events",
        "BOXR_FLAG_ENDPOINT": f"http://127.0.0.1:{gw_port}/flag",
        "BOXR_MODEL": "test/model", "BOXR_MODELS": "test/model",
        "BOXR_OBJECTIVE": "read the flag", "BOXR_MAX_WALL_CLOCK_SEC": "60",
        "BOXR_MAX_COST_MICRO_USD": "5000000",
    }
    task = {"objective": "read the flag", "self": {"ip": "127.0.0.1"},
            "targets": [{"hostname": "127.0.0.1"}]}
    ctx = RunContext.from_env(env, task, now=time.monotonic())
    cfg = Config.load(_config_path(), ctx)
    gateway = Gateway(
        ctx.provider_base_url, ctx.agent_token, budget=ctx.budget,
        retry_headroom_seconds=float(cfg.strategy.get("retry_headroom_seconds", 20) or 0),
        call_timeout=float(cfg.strategy.get("model_call_timeout_seconds", 0) or 0) or None,
    )
    submitter = FlagSubmitter(ctx.flag_endpoint, ctx.event_endpoint, ctx.agent_token)
    try:
        return run(ctx, cfg, gateway=gateway, submitter=submitter)
    finally:
        target.shutdown()
        gateway_server.shutdown()


if __name__ == "__main__":
    result = run_against_rig(exploit_script)
    print(f"exploit run    -> {result}")
    result2 = run_against_rig(noexploit_script)
    print(f"no-exploit run -> {result2}  (mutation check: expect 0 flags)")
    result3 = run_session_rig()
    print(f"session run    -> {result3}  (holds an nc session, sends getflag)")
    result4 = run_delegate_rig()
    print(f"delegate run   -> {result4}  (orchestrator -> web specialist -> capture)")

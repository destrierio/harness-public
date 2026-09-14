"""The tool surface the orchestrator and specialists call, as OpenAI function specs
plus an executor.

Slice 1 tools: shell, submit_flag, record_*, consult_skill (stub).
Slice 2 adds the load-bearing capabilities: session (persistent PTY), python_exec
(persistent kernel), http_request (stateful client), fetch_artifact (workspace),
reverse_shell_listener, and browser (headless Chromium). Every tool is config-gated
and degrades to a message rather than crashing the run.
"""
from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import fields

from .http_client import HttpClient
from .kb import Access, Credential, Finding, Host, Service
from .prompts import SPECIALIST_ROLES
from .python_kernel import PythonKernel
from .sessions import ReverseShellListener, SessionManager
from .workspace import Workspace

# Ceiling on the model's durable NOTES scratchpad (update_notes). Big enough for the
# byte-level RE state that no typed field holds (offsets, opcode/state tables), small
# enough that a runaway scratchpad can never blow the context window on its own.
_NOTES_MAX_CHARS = 8000

_BROWSER_CANDIDATES = (
    ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--dump-dom"],
    ["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--dump-dom"],
    ["chromium-browser", "--headless=new", "--no-sandbox", "--disable-gpu", "--dump-dom"],
    ["chromium", "--headless", "--no-sandbox", "--dump-dom"],
)


def _fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


def _enabled(cfg, key: str) -> bool:
    tools = cfg.tools if isinstance(cfg.tools, dict) else {}
    return bool(tools.get(key, True))


class TurnOutputBudget:
    """Cap tool-message characters for one turn, after flag scanning. Zero is off."""

    def __init__(self, cfg) -> None:
        limit = max(0, int(cfg.tools.get("max_tool_output_per_turn", 0) or 0))
        self.remaining = limit if limit else None

    def take(self, output: str) -> str:
        if self.remaining is None:
            return output
        if len(output) > self.remaining:
            notice = "\n[truncated: per-turn output cap]"
            output = (output[:max(0, self.remaining - len(notice))]
                      + notice[:self.remaining])
        self.remaining -= len(output)
        return output


def parse_tool_call(tc: dict) -> tuple[str, dict]:
    """Extract (name, args) from an OpenAI tool_call, tolerating bad JSON args."""
    fn = tc.get("function", {})
    name = fn.get("name", "")
    try:
        args = json.loads(fn.get("arguments") or "{}")
        if not isinstance(args, dict):
            args = {}
    except (ValueError, TypeError):
        args = {}
    return name, args


def tool_specs(cfg, *, delegate: bool = False, report_done: bool = False) -> list[dict]:
    specs = [
        _fn(
            "shell",
            "Run a bash command on the Kali attacker machine and return its output. "
            "One-shot: use it for scans and one-liners. For anything interactive or "
            "stateful (a foothold shell, gdb, msfconsole), use the session tool.",
            {"command": {"type": "string"}},
            ["command"],
        ),
        _fn(
            "submit_flag",
            "Submit a destrier{...} flag. Submitting is what scores. Safe to call the "
            "moment you see a flag; duplicates are ignored.",
            {"flag": {"type": "string"}},
            ["flag"],
        ),
    ]

    if _enabled(cfg, "enable_session"):
        specs.append(_fn(
            "session",
            "Persistent interactive session that keeps state across calls (cwd, env, a "
            "foothold shell, a live gdb/msfconsole, ssh, an interactive service). "
            "action=open starts one (optional cmd, default bash); action=send writes a "
            "line and returns the output; action=read reads more (for slow output); "
            "action=close ends it; action=list shows open sessions.",
            {
                "action": {"type": "string", "enum": ["open", "send", "read", "close", "list"]},
                "name": {"type": "string", "description": "Session name, e.g. 'foothold' or 'gdb'."},
                "cmd": {"type": "string", "description": "For open: the program to run (default bash)."},
                "data": {"type": "string", "description": "For send: the line/keystrokes to send."},
                "timeout": {"type": "number", "description": "Seconds to wait for output (default 3)."},
            },
            ["action"],
        ))

    if _enabled(cfg, "enable_python_exec"):
        specs.append(_fn(
            "python_exec",
            "Run Python in a persistent kernel with pwntools and requests preimported. "
            "State persists across calls, so an exploit handle (io = process(...)/remote(...)) "
            "survives. The workhorse for exploit development.",
            {
                "code": {"type": "string"},
                "timeout": {"type": "number", "description": "Seconds before the call is aborted (default 60)."},
            },
            ["code"],
        ))

    if _enabled(cfg, "enable_http_request"):
        specs.append(_fn(
            "http_request",
            "Make an HTTP(S) request with a persistent cookie jar (auth survives across "
            "calls), following redirects, TLS not verified. Returns status, headers, body.",
            {
                "method": {"type": "string"},
                "url": {"type": "string"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "auth": {"type": "object", "description": "Optional {username, password} for HTTP Basic/Digest auth, auto-negotiated on a 401 (e.g. an IP camera's digest login)."},
                "proxy": {"type": "string", "description": "Optional SOCKS5 proxy 'host:port' (e.g. a pivot's local SOCKS from ssh -D / chisel) to reach an inner host."},
            },
            ["method", "url"],
        ))

    if _enabled(cfg, "enable_reverse_shell"):
        specs.append(_fn(
            "reverse_shell_listener",
            "Listen for a reverse shell on the attacker machine. action=start (optional "
            "port) returns the LHOST:port to put in your payload; when a connection is "
            "caught it becomes a session named 'revshell' you drive with the session tool. "
            "action=status reports it; action=stop closes the listener.",
            {
                "action": {"type": "string", "enum": ["start", "stop", "status"]},
                "port": {"type": "integer"},
            },
            ["action"],
        ))

    if _enabled(cfg, "enable_fetch_artifact"):
        specs.append(_fn(
            "fetch_artifact",
            "Pull a target file/binary into the /workspace and register it (name, path, "
            "sha256) so it persists. Give a url to download, or a path already on disk to "
            "register. Use it before analysing a binary in the pwn workflow.",
            {
                "url": {"type": "string"},
                "path": {"type": "string"},
                "name": {"type": "string"},
            },
            [],
        ))

    if _enabled(cfg, "enable_browser"):
        specs.append(_fn(
            "browser",
            "Fetch a URL through a headless browser and return the rendered DOM. Use only "
            "when a page needs JavaScript to render; prefer http_request otherwise.",
            {"url": {"type": "string"}},
            ["url"],
        ))

    specs += [
        _fn("record_service", "Record a discovered service so it persists.",
            {"host": {"type": "string"}, "port": {"type": "integer"}, "proto": {"type": "string"},
             "product": {"type": "string"}, "version": {"type": "string"}, "notes": {"type": "string"}},
            ["host", "port"]),
        _fn("record_finding", "Record a lead or confirmed vulnerability.",
            {"host": {"type": "string"}, "service": {"type": "string"}, "cls": {"type": "string"},
             "status": {"type": "string", "enum": ["suspected", "confirmed", "exploited", "dead"]},
             "evidence": {"type": "string"}, "next_action": {"type": "string"}},
            ["host", "cls", "status"]),
        _fn("record_credential", "Record a credential and where it works.",
            {"value": {"type": "string"}, "where_found": {"type": "string"},
             "works_on": {"type": "string"}, "privilege": {"type": "string"}},
            ["value"]),
        _fn("record_access", "Record a foothold: a session on a host at some privilege.",
            {"host": {"type": "string"}, "session": {"type": "string"}, "user": {"type": "string"},
             "privilege": {"type": "string", "enum": ["user", "root", "administrator"]},
             "how": {"type": "string"}},
            ["host"]),
        _fn("record_host", "Record a host and how it is reached (direct, or via a "
            "foothold/pivot session name) so the network topology persists across turns.",
            {"address": {"type": "string"}, "hostname": {"type": "string"},
             "reachable_via": {"type": "string"}, "notes": {"type": "string"}},
            ["address"]),
        _fn("consult_skill",
            "Load a technique playbook (e.g. 'sqli', 'heap-tcache', 'linux-privesc') for "
            "step-by-step method and exact commands.",
            {"name": {"type": "string"}}, ["name"]),
    ]

    if bool((cfg.strategy if isinstance(cfg.strategy, dict) else {}).get("planning", False)):
        specs.append(_fn(
            "update_plan",
            "Maintain your ranked attack plan. Pass the FULL ordered list of steps "
            "(highest-priority first); it replaces the previous plan. Each step: "
            "{goal, status: open|active|done|abandoned, note}. Revise it whenever a "
            "finding changes your strategy — it persists in the SITUATION across turns.",
            {"steps": {"type": "array", "items": {"type": "object", "properties": {
                "goal": {"type": "string"}, "status": {"type": "string"}, "note": {"type": "string"}}}}},
            ["steps"],
        ))
        specs.append(_fn(
            "update_notes",
            "Your durable scratchpad. Pass the FULL notes text; it REPLACES the previous "
            "notes. Keep here exactly what a transcript trim would otherwise destroy: byte "
            "layouts, offsets, struct/opcode/state tables, and which documented values you "
            "have VERIFIED against the binary vs proven PLANTED (decoys). It persists in the "
            "SITUATION every turn — record state here instead of restating it in chat.",
            {"notes": {"type": "string"}},
            ["notes"],
        ))

    if delegate and _enabled(cfg, "enable_specialists"):
        specs.append(_fn(
            "delegate",
            "Hand a single bounded goal to a specialist sub-agent that works it in an "
            "isolated context and reports back. Use it to focus deep effort: 'recon' to "
            "enumerate a surface, 'web' to exploit a web service, 'pwn' to exploit a "
            "binary (heap/ROP), 'privesc' to escalate from a foothold. Findings, "
            "credentials, sessions and flags it produces are shared with you.",
            {
                "specialist": {"type": "string", "enum": list(SPECIALIST_ROLES)},
                "goal": {"type": "string", "description": "One concrete, bounded objective."},
            },
            ["specialist", "goal"],
        ))

    if report_done:
        specs.append(_fn(
            "report_done",
            "Finish this assignment and return control to the orchestrator. Call it when "
            "you capture the flag, gain what you were sent for, or have exhausted your "
            "approaches.",
            {
                "outcome": {"type": "string", "enum": ["success", "partial", "dead_end"]},
                "summary": {"type": "string", "description": "What you achieved and what remains."},
            },
            ["outcome", "summary"],
        ))
    return specs


def _only_known(cls, kw: dict) -> dict:
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in kw.items() if k in names}


Runner = Callable[..., "subprocess.CompletedProcess"]


class ToolExecutor:
    def __init__(
        self,
        ctx,
        kb,
        submitter,
        cfg,
        *,
        runner: Runner = subprocess.run,
        sessions: SessionManager | None = None,
        kernel: PythonKernel | None = None,
        http: HttpClient | None = None,
        workspace: Workspace | None = None,
        listener: ReverseShellListener | None = None,
        browser_runner: Runner | None = None,
        gateway=None,
        now=None,
        skills=None,
    ) -> None:
        self.ctx = ctx
        self.kb = kb
        self.submitter = submitter
        self.cfg = cfg
        self._runner = runner
        self._gateway = gateway
        self._now = now
        tools = cfg.tools if isinstance(cfg.tools, dict) else {}
        self._timeout = int(tools.get("shell_timeout_seconds", 120) or 120)
        self._limit = int(tools.get("shell_output_limit", 8000) or 8000)
        self._session_timeout = float(tools.get("session_read_timeout", 3.0) or 3.0)
        self._python_timeout = float(tools.get("python_timeout_seconds", 60.0) or 60.0)
        # lazily created so Slice 1 call sites (and tests) that never touch them pay nothing
        self._sessions = sessions
        self._kernel = kernel
        self._http = http
        self._workspace = workspace
        self._listener = listener
        self._browser_runner = browser_runner or subprocess.run
        self._skills = skills

    # --- lazy resources ---------------------------------------------------
    def sessions(self) -> SessionManager:
        if self._sessions is None:
            self._sessions = SessionManager()
        return self._sessions

    def kernel(self) -> PythonKernel:
        if self._kernel is None:
            self._kernel = PythonKernel()
        return self._kernel

    def http(self) -> HttpClient:
        if self._http is None:
            self._http = HttpClient()
        return self._http

    def workspace(self) -> Workspace:
        if self._workspace is None:
            self._workspace = Workspace()
        return self._workspace

    def listener(self) -> ReverseShellListener:
        if self._listener is None:
            self._listener = ReverseShellListener(self.sessions())
        return self._listener

    def skills(self):
        if self._skills is None:
            from .skills import SkillLibrary
            self._skills = SkillLibrary.load()
        return self._skills

    def _trim(self, text: str) -> str:
        if len(text) > self._limit:
            return text[: self._limit] + f"\n...[truncated, {len(text)} bytes total]"
        return text

    def execute(self, name: str, arguments: dict) -> str:
        arguments = arguments or {}
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            return f"unknown tool: {name!r}"
        try:
            return handler(arguments)
        except Exception as exc:  # noqa: BLE001 - a tool error is data for the model, never fatal
            return f"tool {name} errored: {exc}"

    def close(self) -> None:
        if self._sessions is not None:
            self._sessions.close_all()
        if self._kernel is not None:
            self._kernel.close()
        if self._listener is not None:
            self._listener.stop()

    # --- Slice 1 tools ----------------------------------------------------
    def _tool_shell(self, args: dict) -> str:
        command = str(args.get("command", "")).strip()
        if not command:
            return "shell: no command given"
        try:
            proc = self._runner(["bash", "-c", command], capture_output=True, text=True, timeout=self._timeout)
        except subprocess.TimeoutExpired:
            return f"command timed out after {self._timeout}s"
        out = proc.stdout or ""
        if proc.stderr:
            out = f"{out}\n[stderr]\n{proc.stderr}" if out else proc.stderr
        return self._trim(out or "(no output)")

    def _tool_submit_flag(self, args: dict) -> str:
        flag = str(args.get("flag", "")).strip()
        if not flag:
            return "submit_flag: no flag given"
        result = self.submitter.submit(flag)
        if result.captured:
            return f"captured {flag}"
        if result.duplicate:
            return f"{flag} already submitted"
        return f"{flag} was not accepted (captured:false)"

    def _tool_record_service(self, args: dict) -> str:
        self.kb.record_service(**_only_known(Service, args))
        return "recorded service"

    def _tool_record_finding(self, args: dict) -> str:
        self.kb.record_finding(**_only_known(Finding, args))
        return "recorded finding"

    def _tool_record_credential(self, args: dict) -> str:
        self.kb.record_credential(**_only_known(Credential, args))
        return "recorded credential"

    def _tool_record_access(self, args: dict) -> str:
        self.kb.record_access(**_only_known(Access, args))
        access = self.kb.accesses[-1]
        strategy = self.cfg.strategy if isinstance(self.cfg.strategy, dict) else {}
        if bool(strategy.get("verify_access", False)):
            name = str(args.get("session", "")).strip()
            verified = False
            if name and self.sessions().has(name):
                out = self.sessions().send(name, "id", timeout=self._session_timeout)
                verified = "uid=" in out
            access.verified = verified
            if verified:
                return "recorded access (verified: id returned a uid)"
            return ("recorded access but UNVERIFIED — no shell confirmed. Open/drive the "
                    "session and confirm with `id` before relying on this foothold.")
        return "recorded access"

    def _tool_record_host(self, args: dict) -> str:
        self.kb.record_host(**_only_known(Host, args))
        return "recorded host"

    def _tool_update_plan(self, args: dict) -> str:
        steps = args.get("steps")
        if not isinstance(steps, list):
            return "update_plan: pass steps=[{goal,status,note}, ...]"
        self.kb.set_plan(steps)
        return f"plan updated ({len(self.kb.plan)} steps)"

    def _tool_update_notes(self, args: dict) -> str:
        notes = args.get("notes")
        if not isinstance(notes, str):
            return "update_notes: pass notes='...'"
        capped = notes[:_NOTES_MAX_CHARS]
        self.kb.set_notes(capped)
        suffix = " (truncated)" if len(notes) > _NOTES_MAX_CHARS else ""
        return f"notes updated ({len(capped)} chars){suffix}"

    def _tool_consult_skill(self, args: dict) -> str:
        name = str(args.get("name", "")).strip()
        skill = self.skills().get(name)
        if skill is None:
            available = ", ".join(self.skills().names()) or "(none)"
            return f"no skill named {name!r}. Available: {available}"
        return f"# SKILL: {skill.name}\n\n{skill.body}"

    def _tool_delegate(self, args: dict) -> str:
        import time as _time

        from .prompts import SPECIALIST_ROLES as _ROLES
        from .subagent import run_specialist

        if self._gateway is None:
            return "delegation is unavailable in this context"
        role = str(args.get("specialist") or args.get("role") or "").strip()
        goal = str(args.get("goal", "")).strip()
        if role not in _ROLES:
            return f"unknown specialist {role!r}; choose from {list(_ROLES)}"
        if not goal:
            return "delegate: give the specialist a concrete goal"
        result = run_specialist(
            role,
            goal,
            ctx=self.ctx,
            cfg=self.cfg,
            gateway=self._gateway,
            submitter=self.submitter,
            kb=self.kb,
            executor=self,
            now=self._now or _time.monotonic,
        )
        return f"[{role} {result.outcome} in {result.turns} turns] {result.summary}"

    # --- Slice 2 tools ----------------------------------------------------
    def _tool_session(self, args: dict) -> str:
        action = str(args.get("action", "")).strip()
        name = str(args.get("name", "")).strip()
        timeout = float(args.get("timeout") or self._session_timeout)
        mgr = self.sessions()
        if action == "list":
            return "open sessions: " + (", ".join(mgr.list()) or "(none)")
        if action == "open":
            cmd = args.get("cmd")
            argv = ["bash", "-c", str(cmd)] if cmd else None
            mgr.open(name, cmd=argv)
            banner = mgr.read(name, timeout=min(timeout, 1.0))
            return self._trim(f"opened session {name!r}\n{banner}".rstrip())
        if not name or not mgr.has(name):
            return f"no such session {name!r}; open it first"
        if action == "send":
            return self._trim(mgr.send(name, str(args.get("data", "")), timeout=timeout))
        if action == "read":
            return self._trim(mgr.read(name, timeout=timeout))
        if action == "close":
            mgr.close(name)
            return f"closed session {name!r}"
        return f"unknown session action {action!r}"

    def _tool_python_exec(self, args: dict) -> str:
        code = str(args.get("code", ""))
        if not code.strip():
            return "python_exec: no code given"
        timeout = float(args.get("timeout") or self._python_timeout)
        return self._trim(self.kernel().exec(code, timeout=timeout))

    def _tool_http_request(self, args: dict) -> str:
        method = str(args.get("method", "GET"))
        url = str(args.get("url", "")).strip()
        if not url:
            return "http_request: no url given"
        headers = args.get("headers") if isinstance(args.get("headers"), dict) else None
        auth = args.get("auth") if isinstance(args.get("auth"), dict) else None
        kwargs = {"headers": headers, "body": args.get("body"), "auth": auth}
        if isinstance(args.get("proxy"), str) and args["proxy"].strip():
            kwargs["proxy"] = args["proxy"].strip()
        resp = self.http().request(method, url, **kwargs)
        head = "\n".join(f"{k}: {v}" for k, v in list(resp["headers"].items())[:12])
        return self._trim(f"status: {resp['status']}\n{head}\n\n{resp['body']}")

    def _tool_reverse_shell_listener(self, args: dict) -> str:
        action = str(args.get("action", "")).strip()
        lst = self.listener()
        lhost = self.ctx.self_ip or "0.0.0.0"
        if action == "start":
            port = int(args.get("port") or 4444)
            lst.start(port=port)
            return (f"listening on {lhost}:{lst.port}. Use LHOST={lhost} LPORT={lst.port} in your "
                    f"payload; a caught shell becomes session '{lst.session_name}'.")
        if action == "status":
            st = lst.status()
            return f"listener: {json.dumps(st)}"
        if action == "stop":
            lst.stop()
            return "listener stopped"
        return f"unknown reverse_shell_listener action {action!r}"

    def _tool_fetch_artifact(self, args: dict) -> str:
        ws = self.workspace()
        url = str(args.get("url", "")).strip()
        path = str(args.get("path", "")).strip()
        name = args.get("name")
        if url:
            art = ws.fetch_url(url, self.http(), name=name)
        elif path:
            art = ws.register_path(path)
        else:
            return "fetch_artifact: give a url or a path"
        self.kb.record_artifact(name=art.name, path=art.path, sha256=art.sha256, source=art.source)
        return f"fetched {art.name} -> {art.path} (sha256 {art.sha256[:16]}...)"

    def _tool_browser(self, args: dict) -> str:
        url = str(args.get("url", "")).strip()
        if not url:
            return "browser: no url given"
        last_err = ""
        for argv in _BROWSER_CANDIDATES:
            try:
                proc = self._browser_runner(argv + [url], capture_output=True, text=True, timeout=self._timeout)
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                return f"browser timed out after {self._timeout}s"
            out = proc.stdout or proc.stderr or ""
            return self._trim(out or "(empty page)")
        return f"no headless browser available in this image ({last_err})"

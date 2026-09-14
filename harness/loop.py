"""The orchestrator loop.

The single most important property: it is bounded ONLY by the platform's cost cap
(gateway 402), the wall-clock deadline, or the platform tearing the cell down.
There is no turn cap, no step cap, no default give-up. Anti-stall logic only
changes behavior (nudges a technique switch); it never ends the run.

Focus discipline (all opt-in via strategy.* keys, default off, never box-specific):
history trimming keeps the transcript bounded so a slow model gets more actions per
deadline; a commit nudge stops pre-foothold thrash; a turn guard refuses exact
repeats and post-foothold rescans; and an auto-loot sweep does the boring flag hunt
the moment a foothold lands. See config.yaml for the switches.
"""
from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import log
from .config import Config
from .coverage import coverage_report
from .gateway import CostExhausted, Deadline, GatewayError, ModelNotPermitted, UpstreamUnavailable
from .kb import KB, classify_objective, staged_goal, win_condition_text
from .prompts import ORCHESTRATOR_SYSTEM, SUMMARIZER_SYSTEM, TRIAGE_SYSTEM
from .runtime import RunContext
from .skills import augment_system
from .tools import ToolExecutor, TurnOutputBudget, parse_tool_call, tool_specs

FINAL_PUSH_SECONDS = 60

# A provider brownout — transient upstream failures (timeouts / 5xx / empty-200
# upstream_error) exhausting the gateway's retry cap while budget AND wall-clock still
# have room — must NOT end the run. It usually clears in under a minute, and we may
# already hold flags; ending here throws away the rest of the budget (a regression run: a
# glm-5.3 brownout ended a run at 46% budget spent, user flag already captured). On
# UpstreamUnavailable the loop sleeps a short cooldown and re-enters, up to this many
# CONSECUTIVE times (a good call resets the streak) before giving up. Always on: unlike
# the focus-discipline knobs, riding out a transient hiccup is never undesirable.
_BROWNOUT_COOLDOWN_SECONDS = 30.0
_MAX_BROWNOUT_COOLDOWNS = 4

# Rough tokens-per-char for transcript-size estimation (context-aware trimming). ~0.3
# slightly over-counts vs a real tokenizer, so we compact a touch early rather than
# overrun the model's context window.
_TOKENS_PER_CHAR = 0.30
# Ceiling for the calibrated ratio (see _calibrated_per_char): the char->token ratio is
# corrected upward from the model's REAL prompt_tokens, but never past this, so one
# anomalous call cannot over-trim the transcript forever. ~0.45 covers dense code/JSON.
_TOKENS_PER_CHAR_MAX = 0.45

# A line that looks like disassembly or a hex dump: an address column then hex bytes
# (objdump `401136: 55 ...`, xxd `00000000: 7f45 ...`, radare2 `0x00401136  55 ...`).
_DUMP_LINE = re.compile(r"^\s*(?:0x)?[0-9a-fA-F]{4,}:?\s+[0-9a-fA-F]{2}")

# A tool call that STATICALLY reverses a binary (disassembly / static analysis). Repeating
# these for turn after turn with no new finding is the "reading an obfuscated validator by
# hand" trap: static reading mis-slices xor'd constants and computed jump tables. Detecting
# a streak of them (re_emulate_nudge) lets the harness push the agent to dynamic emulation.
_STATIC_RE_RE = re.compile(
    r"(?:^|[\s/])(?:objdump|readelf|rabin2|radare2|rizin|r2|gdb)(?:\s|$)|(?:^|\W)capstone(?:\W|$)"
)
# A tool call that DYNAMICALLY emulates (the baked unicorn helper) — the move we want. Seeing
# one resets the static-churn streak: emulation is progress, not thrash.
_EMULATE_RE = re.compile(r"re_emulate|emu_start|unicorn|\bUc\(")

# A self-recap: a whole assistant turn spent re-writing a summary of prior state as chat,
# instead of taking an action. The model does this after a trim shrinks its context, to
# hoard state — but durable state is already re-rendered in the SITUATION every turn, so the
# recap is pure waste AND (a regression run) a vehicle that re-promotes stale conclusions the
# trim keeps destroying. Detected STRUCTURALLY — a large, action-less turn that reads like a
# state document — never by box-specific content.
_RECAP_MARKERS = re.compile(
    r"compressed (?:summary|transcript)|updated transcript|pen[- ]?test transcript|"
    r"summary of (?:progress|the run|findings|work)|current state\b|state recap|"
    r"recap of|confirmed facts|already tried|progress recap",
    re.IGNORECASE,
)
_HEADING_LINE = re.compile(r"^\s{0,3}#{1,6}\s+\S")
_RECAP_STUB = (
    "[A full-transcript self-recap was folded into the PROGRESS LOG to save context. "
    "Your durable state — NOTES, PLAN, findings, PROGRESS LOG — is re-shown in SITUATION "
    "every turn, so do NOT re-summarize the transcript as a message: it wastes the turn and "
    "can resurrect a conclusion you already disproved. Spend each turn on an action or a KB "
    "update (update_notes/update_plan/record_finding).]"
)


# The RACE (double-fetch / TOCTOU) verdict re_emulate prints when it detects a check-then-
# commit gate. Capturing it lets the harness PIN it so noisy contradicting evidence can't
# argue it away (a regression run: the verdict reached the model ~5x, then it reverted to a static
# frame anyway and never wrote a line of concurrent-exploit code).
_RACE_VERDICT_RE = re.compile(r"RACE \(double-fetch / TOCTOU\) — NOT statically solvable\.")
# The emulator's verdict names the field and BOTH values on a concrete line; a skill/prompt
# explainer has the phrase but no such line. Requiring it stops the pin latching onto
# consult_skill output (a regression run pinned exactly that, so the pin carried no values).
_RACE_FIELD_RE = re.compile(r"field \[\+0x[0-9a-fA-F]+\][^\n]*equal[^\n]*0x[0-9a-fA-F]+", re.I)
# Tool calls that BUILD the concurrent exploit (shared memory + fd passing + a flipper / a
# background writer). If the model does this after a confirmed race it is on the right track,
# so the race-build nudge must NOT fire.
_RACE_BUILD_RE = re.compile(
    r"memfd|MAP_SHARED|SCM_RIGHTS|sched_setaffinity|multiprocessing|sendmsg|win_race|Process\(",
    re.IGNORECASE,
)
# The emulator prints these when a frame STATICALLY passes the validator it was aimed at.
# On a check-then-commit daemon that is FALSE COMFORT: the validator accepts PREVIEW, but the
# daemon RE-READS the frame in its request handler and demands COMMIT, so the statically-valid
# frame is exactly the one the live daemon rejects. The model takes "accepted" as a win and
# grinds RE instead of testing live, so the double-fetch is never found (regression-case/regression-case/
# regression-case). We reframe it: prove the frame live; a live rejection of an accepted frame IS the
# race. A race-verdict output is excluded (the race machinery owns that) in _emitted_static_accept.
_STATIC_ACCEPT_RE = re.compile(r"(?m)^\s*(?:accepted:\s*True\b|solve:\s*ACCEPTED\b)")
# A tool call that SUBMITS a frame to the live daemon (a real test, not more reversing): a unix
# socket, a raw send, or win_race itself. win_race also matches _RACE_BUILD_RE, so a win_race
# turn is treated as building first (the prove-live nudge steps aside once the exploit is built).
_LIVE_SUBMIT_RE = re.compile(
    r"\.sock\b|AF_UNIX|SOCK_STREAM|\bsocat\b|sendmsg|\.connect\(|socket\.socket|win_race",
    re.IGNORECASE,
)


def _extract_race_verdict(text: str) -> str | None:
    """Pull the emulator's RACE verdict block out of a tool output — from the 'RACE (double-
    fetch...' line through its actionable 'race-condition-toctou' tail — so it can be pinned
    verbatim (it names the field and values the emulator recovered dynamically, no hardcoding)."""
    if not text:
        return None
    m = _RACE_VERDICT_RE.search(text)
    if not m:
        return None
    tail = text[m.start():]
    if not _RACE_FIELD_RE.search(tail):
        return None   # phrase present but no concrete field+values -> explainer text, not a verdict
    anchor = tail.find("race-condition-toctou")
    if anchor != -1:
        nl = tail.find("\n", anchor)
        tail = tail[: nl if nl != -1 else len(tail)]
    return tail[:800].strip()


def _did_race_build(tool_calls) -> bool:
    """True when a turn's tool calls attempt to build the concurrent race exploit (shared
    memory / fd passing / a background flipper) — the move we want after a confirmed race."""
    for tc in tool_calls or []:
        _name, args = parse_tool_call(tc)
        blob = f"{args.get('command', '')} {args.get('code', '')}"
        if "--selftest" in blob:
            continue   # a rehearsal, not an attack — must NOT silence the build nudge
        if _RACE_BUILD_RE.search(blob):
            return True
    return False

def _emitted_static_accept(text: str) -> bool:
    """True when a tool output reports a frame STATICALLY passing the validator (`accepted:
    True` / `solve: ACCEPTED`) and does NOT also carry the emulator's double-fetch verdict. That
    is the false-comfort a check-then-commit VALIDATOR gives: the second read that demands a
    different value lives in the daemon handler, not this function, so "accepted" is a hypothesis
    to prove live, not a win. An output that already carries the RACE verdict is left to the race
    machinery."""
    if not text or _RACE_VERDICT_RE.search(text):
        return False
    return bool(_STATIC_ACCEPT_RE.search(text))


def _did_live_submit(tool_calls) -> bool:
    """True when a turn actually SUBMITS a frame to the live daemon (unix socket / raw send /
    win_race) — a real test of the static frame, as opposed to yet more static reversing."""
    for tc in tool_calls or []:
        _name, args = parse_tool_call(tc)
        blob = f"{args.get('command', '')} {args.get('code', '')}"
        if _LIVE_SUBMIT_RE.search(blob):
            return True
    return False


def _looks_like_recap(content: str) -> bool:
    """True when text reads like a state-summary document — several markdown headings or a
    recap phrase. Generic (structure + common recap words), never a box's specific content."""
    if not content:
        return False
    headings = sum(1 for ln in content.splitlines() if _HEADING_LINE.match(ln))
    return headings >= 2 or bool(_RECAP_MARKERS.search(content))


def _is_self_recap(msg: dict, min_chars: int) -> bool:
    """A pure-text assistant turn (no tool call this turn) that reconstructs prior state as a
    large document — the self-recap that burns a turn and re-promotes stale leads. A turn that
    also makes a tool call is an ACTION and is never folded, however long its reasoning is."""
    if msg.get("role") != "assistant" or msg.get("tool_calls"):
        return False
    content = msg.get("content") or ""
    return len(content) >= min_chars and _looks_like_recap(content)


def _fold_recap(progress_log: str, recap: str, max_chars: int) -> str:
    """The model's own comprehensive recap supersedes the rolling summary — make it the
    durable PROGRESS LOG (capped) so its reasoning stays visible in the digest without the
    model re-emitting it as chat."""
    return (recap or progress_log or "").strip()[:max_chars]

# Only stateless, subprocess-backed tools are safe to run concurrently. Everything
# that touches shared state (KB, sessions, the python kernel, the cookie jar, flag
# submission, delegation) stays serial, so speed never costs coherence.
_PARALLEL_SAFE = frozenset({"shell", "browser"})

# Door-knocking scanners: refused (when focus_after_foothold is on) once we already
# hold a shell, so the agent stops re-scanning and drives the access it has.
_RECON_TOOLS = frozenset({
    "nmap", "masscan", "rustscan", "unicornscan", "gobuster", "ffuf", "dirb",
    "dirbuster", "feroxbuster", "wfuzz", "nikto", "whatweb", "sslscan", "dnsrecon",
    "fierce", "enum4linux", "wpscan",
})

# A generic, read-only sweep run automatically on a fresh foothold: identity, easy
# privesc signal, and the flag itself in the usual places. Nothing box-specific.
# The flag globs MUST include the standard CTF filenames — user.txt / root.txt / local.txt
# (a regression run lost the user flag because /home/dev/user.txt was not in the glob), and the
# content grep prints the destrier{...} TOKEN itself (not just the filename, which the flag
# scanner cannot submit).
_LOOT_SWEEP = (
    "id; uname -a; hostname; echo '--SUDO--'; sudo -n -l 2>/dev/null | head -40",
    "echo '--FLAGS--'; for f in /flag /flag.txt /root/flag /root/flag.txt "
    "/root/root.txt /root/user.txt /home/*/flag* /home/*/user.txt /home/*/root.txt "
    "/home/*/local.txt /home/*/proof.txt /home/*/*.txt /var/*flag* /tmp/*flag* /flag/* "
    "/usr/share/flag*; do [ -f \"$f\" ] && echo \"== $f ==\" && cat \"$f\"; done 2>/dev/null; "
    "grep -rhoIE 'destrier\\{[a-z0-9_]*\\}' /home /root /tmp /opt /srv /var/www /etc "
    "2>/dev/null | head",
    "echo '--SUID--'; find / -perm -4000 -type f 2>/dev/null | head -40; "
    "echo '--HOME--'; ls -la /root /home/* 2>/dev/null | head -60",
)


def _is_recon_command(command: str) -> bool:
    for tok in re.findall(r"[A-Za-z0-9_./-]+", command or ""):
        if tok.rsplit("/", 1)[-1] in _RECON_TOOLS:
            return True
    return False


def _repeat_sig(name: str, args: dict) -> str:
    if name == "shell":
        return "shell::" + " ".join(str(args.get("command", "")).split())
    if name == "http_request":
        return "http::%s %s" % (
            str(args.get("method", "GET")).upper(), str(args.get("url", "")).strip()
        )
    return ""


class _TurnGuard:
    """Refuses two kinds of wasted call, both opt-in: an exact-duplicate probe that
    already ran (force a fresh idea), and a fresh scan issued after we already hold a
    foothold (stop looking for more doors). Refusals are data for the model, not
    errors — the call simply does not execute and the model reads why."""

    def __init__(self, kb: KB, *, refuse_repeats: bool, focus_after_foothold: bool) -> None:
        self.kb = kb
        self.refuse_repeats = refuse_repeats
        self.focus_after_foothold = focus_after_foothold
        self._seen: dict[str, int] = {}

    def __call__(self, name: str, args: dict) -> str | None:
        if (
            self.focus_after_foothold
            and self.kb.verified_accesses()
            and name == "shell"
            and _is_recon_command(str(args.get("command", "")))
        ):
            return (
                "REFUSED: you already have a foothold shell — stop scanning for new "
                "entry points. Drive the shell you have: read the flag, or escalate if "
                "it is privilege-gated. Run this inside the foothold session only if you "
                "genuinely need it there."
            )
        if self.refuse_repeats and name in ("shell", "http_request"):
            sig = _repeat_sig(name, args)
            if sig and self._seen.get(sig):
                self._seen[sig] += 1
                return (
                    f"REFUSED: this exact {name} already ran and changed nothing. Change "
                    "the technique (a different path, port, encoding, or tool) or move on "
                    "and record the dead end with record_finding(status='dead')."
                )
            if sig:
                self._seen[sig] = 1
        return None


def execute_tool_calls(tool_calls, executor, cap: int, guard=None) -> list[tuple[dict, str]]:
    """Run a turn's tool calls, overlapping the parallel-safe ones (up to `cap`)
    while keeping stateful ones serial. A guard may refuse a call before it runs;
    a refused call yields the refusal string instead of executing. Returns
    (tool_call, output) in input order."""
    outputs: list[str | None] = [None] * len(tool_calls)
    parsed = [parse_tool_call(tc) for tc in tool_calls]
    refusals: dict[int, str] = {}
    if guard is not None:
        for i, (name, args) in enumerate(parsed):
            msg = guard(name, args)
            if msg:
                refusals[i] = msg
    runnable = [i for i in range(len(tool_calls)) if i not in refusals]
    parallel = [i for i in runnable if parsed[i][0] in _PARALLEL_SAFE]
    serial = [i for i in runnable if i not in set(parallel)]

    if cap > 1 and len(parallel) > 1:
        with ThreadPoolExecutor(max_workers=cap) as pool:
            futures = {pool.submit(lambda i=i: executor.execute(*parsed[i])): i for i in parallel}
            for fut, i in futures.items():
                outputs[i] = fut.result()
    else:
        for i in parallel:
            outputs[i] = executor.execute(*parsed[i])
    for i in serial:
        outputs[i] = executor.execute(*parsed[i])
    for i, msg in refusals.items():
        outputs[i] = msg
    return [(tool_calls[i], outputs[i] or "") for i in range(len(tool_calls))]


def _history_cut_index(history: list[dict], max_turns: int) -> int:
    """Index at which to slice history to keep the last `max_turns` assistant-led
    turns (cutting on an assistant boundary preserves the assistant->tool pairing the
    API requires). Returns 0 when nothing is dropped. 0/negative max_turns = unlimited."""
    if max_turns <= 0:
        return 0
    assistant_idx = [i for i, m in enumerate(history) if m.get("role") == "assistant"]
    if len(assistant_idx) <= max_turns:
        return 0
    return assistant_idx[-max_turns]


def _trim_history(history: list[dict], max_turns: int) -> list[dict]:
    """Drop old turns, keeping the last `max_turns` assistant-led blocks. Durable
    facts survive in the KB digest, which is re-rendered every turn, so the
    transcript can be compacted without losing state. 0 = unlimited."""
    cut = _history_cut_index(history, max_turns)
    return history[cut:] if cut else history


def _message_chars(messages) -> int:
    """Character size of a message list: content + serialized tool_calls + per-message
    framing. The raw input to the token estimate, split out so the char->token ratio can
    be calibrated against the model's real prompt_tokens (see _calibrated_per_char)."""
    chars = 0
    for m in messages:
        c = m.get("content")
        if c:
            chars += len(c) if isinstance(c, str) else len(str(c))
        tcs = m.get("tool_calls")
        if tcs:
            try:
                chars += len(json.dumps(tcs))
            except (TypeError, ValueError):
                chars += len(str(tcs))
        chars += 8  # role/message framing overhead
    return chars


def _estimate_tokens(messages, per_char: float = _TOKENS_PER_CHAR) -> int:
    """Rough token count of a message list: _message_chars * per_char. Deliberately
    approximate — it drives a 'compact to a focus budget' decision, not exact accounting.
    per_char is calibrated from the real prompt_tokens over the run so the estimate tracks
    the actual tokenizer rather than a fixed guess."""
    return int(_message_chars(messages) * per_char)


def _calibrated_per_char(current: float, *, real_tokens: int, chars_sent: int,
                         lo: float = _TOKENS_PER_CHAR, hi: float = _TOKENS_PER_CHAR_MAX) -> float:
    """Correct the char->token ratio from the model's REAL prompt_tokens for the prompt
    we actually sent. SAFETY VALVE: the ratio may only ever RATCHET UP (never down), so
    the estimate can only ever trim MORE, never less — a dense tokenizer can never cause
    under-trimming, and this can never recreate the unbounded-growth regression. Clamped
    to [lo, hi] so one anomalous call cannot over-trim forever. No measurement (either
    value <= 0) leaves the ratio unchanged."""
    if real_tokens <= 0 or chars_sent <= 0:
        return current
    observed = real_tokens / chars_sent
    return min(hi, max(lo, current, observed))


def _history_cut_index_by_tokens(
    history: list[dict], *, budget_tokens: int, fraction: float,
    overhead_tokens: int, min_keep_turns: int, per_char: float = _TOKENS_PER_CHAR,
) -> int:
    """Context-aware analogue of _history_cut_index: keep the MOST-RECENT assistant-led
    turns that fit under `fraction * budget_tokens` (leaving room for overhead — system
    prompt, tool specs, SITUATION digest — and the completion), cutting on an assistant
    boundary. Always keep at least `min_keep_turns` assistant turns so the immediate
    working set is never stripped, even if it alone exceeds the target. 0 = keep all.
    This is what lets a 128K model actually use its window instead of compacting at a
    fixed turn count (~10%)."""
    if budget_tokens <= 0:
        return 0
    assistant_idx = [i for i, m in enumerate(history) if m.get("role") == "assistant"]
    keep_floor = max(1, min_keep_turns)
    if len(assistant_idx) <= keep_floor:
        return 0
    target = max(0, int(fraction * budget_tokens))
    max_k = len(assistant_idx) - keep_floor      # deepest allowed cut (keeps keep_floor turns)
    for k in range(0, max_k + 1):
        cut = assistant_idx[k] if k > 0 else 0
        if overhead_tokens + _estimate_tokens(history[cut:], per_char) <= target:
            return cut
    return assistant_idx[max_k]


def _compaction_cut_index(
    history: list[dict], *, max_turns: int, budget_tokens: int, fraction: float,
    overhead_tokens: int, min_keep_turns: int, per_char: float = _TOKENS_PER_CHAR,
) -> int:
    """Combined trim point: apply BOTH the turn cap and the token budget and take the
    MORE AGGRESSIVE cut (the larger index drops more). The two are complementary bounds,
    not alternatives — the turn cap enforces FOCUS (a bounded recent working set) and the
    token budget catches an over-large window. A token budget must NEVER silently disable
    the turn cap: doing so let a large-window model grow its transcript unbounded (~300
    messages) and drown, losing the flag. 0 = keep all."""
    turn_cut = _history_cut_index(history, max_turns) if max_turns else 0
    token_cut = (
        _history_cut_index_by_tokens(
            history, budget_tokens=budget_tokens, fraction=fraction,
            overhead_tokens=overhead_tokens, min_keep_turns=min_keep_turns, per_char=per_char)
        if budget_tokens > 0 else 0
    )
    return max(turn_cut, token_cut)


def _is_machine_code_dump(text: str) -> bool:
    """True when output looks like disassembly or a hex dump (address column then hex
    bytes on most lines). Triage must never lossily summarize it — the bytes are the
    point of reverse-engineering — so it is passed through verbatim."""
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if len(lines) < 5:
        return False
    sample = lines[:60]
    hits = sum(1 for ln in sample if _DUMP_LINE.match(ln))
    return hits >= 5 and hits >= len(sample) * 0.5


def _summarize_dropped(dropped, prior, gateway, cfg, ctx, *, now, max_chars: int = 2000) -> str:
    """Fold a dropped transcript slice into a rolling progress note via the cheap
    summarizer model, so trimming keeps reasoning (not just typed KB facts). Returns
    the prior note unchanged on any failure/empty result."""
    if not dropped or gateway is None:
        return prior
    text = "\n".join(
        f"{m.get('role')}: {m.get('content') or ''}" for m in dropped if m.get("content")
    )
    if not text.strip():
        return prior
    try:
        model = cfg.model_for("summarizer", ctx)
        result = gateway.chat(
            model,
            [{"role": "system", "content": cfg.prompts.get("summarizer_system") or SUMMARIZER_SYSTEM},
             {"role": "user", "content": (f"Prior progress:\n{prior}\n\n" if prior else "") + f"Newer turns:\n{text}"}],
            temperature=_temperature(cfg, "summarizer"), effort=_effort(cfg, "summarizer"), now=now,
        )
    except Exception:  # noqa: BLE001 - a summary failure must never end the run
        return prior
    summary = (result.content or "").strip()
    return (summary or prior)[:max_chars]


def _foothold_session_names(kb: KB, executor: ToolExecutor) -> list[str]:
    try:
        mgr = executor.sessions()
    except Exception:  # noqa: BLE001
        return []
    names: list[str] = []
    for a in kb.verified_accesses():
        n = (a.session or "").strip()
        if n and mgr.has(n) and n not in names:
            names.append(n)
    if mgr.has("revshell") and "revshell" not in names:
        names.append("revshell")
    return names


def _foothold_loot_targets(kb: KB, executor: ToolExecutor) -> list[tuple[str, str]]:
    """(session, user) for every live foothold. Keyed by user as well as session so that
    ESCALATING within a session (postgres -> su dev -> root) re-loots it as the new user —
    a flag only that user can read (e.g. /home/dev/user.txt, unreadable as postgres) is
    grabbed the moment the escalated access is recorded, not left on the table."""
    try:
        mgr = executor.sessions()
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, str]] = []
    for a in kb.verified_accesses():
        n = (a.session or "").strip()
        pair = (n, a.user or "")
        if n and mgr.has(n) and pair not in out:
            out.append(pair)
    if mgr.has("revshell") and not any(s == "revshell" for s, _ in out):
        out.append(("revshell", ""))
    return out


def _auto_loot(executor: ToolExecutor, session_name: str, submitter, timeout: float = 8.0) -> str:
    """Run the generic read-only sweep in a foothold session, scanning every chunk
    for flags (so a printed flag is submitted immediately). Returns the transcript."""
    mgr = executor.sessions()
    chunks: list[str] = []
    for cmd in _LOOT_SWEEP:
        try:
            out = mgr.send(session_name, cmd, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - a loot step failing is not fatal
            out = f"(loot step failed: {exc})"
        submitter.scan(out)
        chunks.append(out)
    text = "\n".join(chunks)
    return text[:6000] + ("\n...[truncated]" if len(text) > 6000 else "")


@dataclass
class RunResult:
    reason: str  # cost_exhausted | deadline | teardown | gateway_error | upstream_unavailable
    turns: int
    flags_captured: int


def _stall_nudge() -> dict:
    return {
        "role": "user",
        "content": (
            "You have made no new findings for several turns. Change approach: switch "
            "to a different service or attack surface, consult a skill, or try a "
            "different technique. Record dead ends with record_finding(status='dead')."
        ),
    }


def _coverage_nudge(untried: list[str]) -> dict:
    """A stall nudge that points at concrete untried vectors instead of a vague
    'change approach' — the difference between a checklist and dilly-dallying."""
    top = ", ".join(untried[:5])
    return {
        "role": "user",
        "content": (
            f"You've stalled. Untried high-value vectors on the current surface: {top}. "
            f"Pick the most promising one and try it concretely — consult its skill for the "
            f"exact method. If every real option here is exhausted, record the dead ends and "
            f"pivot to another service or host."
        ),
    }


def _emulate_nudge() -> dict:
    return {
        "role": "user",
        "content": (
            "You have been statically disassembling the same target for several turns with "
            "no new findings. STOP hand-tracing — an obfuscated validator (xor'd constants, "
            "opaque predicates, a computed jump table) is exactly what static reading "
            "mis-slices. EMULATE it instead: find the function's address range, then run "
            "`python3 -m harness.re_emulate <bin> --start <addr> --len <n> [--diff]` "
            "(consult_skill 'protocol-reversing'). Record what you recover in update_notes."
        ),
    }


def _prove_live_nudge(tested_live: bool) -> dict:
    if tested_live:
        return {
            "role": "user",
            "content": (
                "You have a frame the EMULATOR accepts but the LIVE daemon does not honor. That discrepancy "
                "IS the check-then-commit (double-fetch) signature: the daemon re-reads the frame after "
                "the first check and demands a DIFFERENT value, so NO static frame will ever pass — reversing "
                "it further is wasted effort. Win it CONCURRENTLY now: `python3 -m harness.win_race --sock "
                "<target.sock> --submit-hex <frame> --field-offset <off> --preview <v1> --commit <v2,v3,...> "
                "--success <status>`. If you cannot pin the second value, pass SEVERAL comma-separated "
                "--commit candidates and let win_race sweep them. Do not hand-write the concurrency. "
                "consult_skill 'race-condition-toctou'."
            ),
        }
    return {
        "role": "user",
        "content": (
            "The emulator reported the frame ACCEPTED — that is a HYPOTHESIS, not a win. A check-then-commit "
            "(double-fetch) daemon RE-READS the frame after it accepts, so a statically-valid frame is often "
            "exactly the one the live daemon rejects on its second read (e.g. PREVIEW passes the validator, "
            "then the handler demands COMMIT). STOP reversing and PROVE it: submit this EXACT frame to the "
            "live daemon now (connect to the target socket and send it). If the daemon REJECTS a frame the "
            "emulator accepted, that gap IS a double-fetch race — do not reverse further, win it CONCURRENTLY: "
            "`python3 -m harness.win_race --sock <target.sock> --submit-hex <frame> --field-offset <off> "
            "--preview <v1> --commit <v2,...> --success <status>` (sweep several --commit candidates if "
            "unsure). consult_skill 'race-condition-toctou'."
        ),
    }


def _race_build_nudge() -> dict:
    return {
        "role": "user",
        "content": (
            "The emulator CONFIRMED the root gate is a double-fetch (check-then-commit) race, "
            "yet you have spent several turns NOT building the concurrent exploit. A single "
            "static buffer can NEVER pass — the field is re-read and must hold DIFFERENT values "
            "between reads. Running --selftest is a REHEARSAL, not an attack. STOP reversing/"
            "rehearsing and FIRE at the target NOW: `python3 -m harness.win_race --sock <target.sock> "
            "--submit-hex <frame> --field-offset <off> --preview <v1> --commit <v2> --success "
            "<status>`. If you cannot pin the SECOND value (its read hides behind a skipped call), "
            "either point re_emulate --start at the DECISION function where both reads happen, or "
            "pass SEVERAL candidate --commit values (comma-separated) and let win_race sweep them. "
            "consult_skill 'race-condition-toctou'. Do not hand-write the concurrency."
        ),
    }


def _discovery_count(kb) -> int:
    """Count of SUBSTANTIVE facts the run has discovered (findings/services/credentials/
    accesses/flags/artifacts). Unlike `kb.fingerprint()` this deliberately EXCLUDES
    progress_log, notes, plan, dead_ends and phase — those churn on history-summarisation
    (every trim rewrites progress_log; the model rewrites notes/plan) WITHOUT any new
    discovery. Using the fingerprint to gate the RE-static streak let that churn masquerade
    as progress and reset the streak, so the emulate nudge never fired (a regression run: 0
    nudges across 93 turns despite ~15 hand-disassembly turns, because constant self-recaps
    forced frequent trims that rewrote progress_log). Reset the streak only on a real new
    discovery (this count rising) or an actual emulation."""
    return (len(kb.findings) + len(kb.services) + len(kb.credentials)
            + len(kb.accesses) + len(kb.flags) + len(kb.artifacts))


def _re_call_kinds(tool_calls) -> tuple[bool, bool]:
    """(did_static_re, did_emulate) for a turn's tool calls — inspecting the shell command
    or python code each one runs. Drives the re_emulate_nudge streak."""
    did_static = did_emulate = False
    for tc in tool_calls or []:
        _name, args = parse_tool_call(tc)
        blob = f"{args.get('command', '')} {args.get('code', '')}"
        if _EMULATE_RE.search(blob):
            did_emulate = True
        elif _STATIC_RE_RE.search(blob):
            did_static = True
    return did_static, did_emulate


def _commit_nudge() -> dict:
    return {
        "role": "user",
        "content": (
            "You now hold credentials AND at least one candidate weakness, but no "
            "foothold yet. STOP enumerating. Pick the SINGLE most promising exploit and "
            "drive it to an interactive session (shell) now — enable telnet/ssh via a "
            "config write, fire the CVE, or use the creds against a login/SSH. Consider "
            "handing it to a specialist with delegate. Recon finds doors; you can open "
            "one — stop looking for more."
        ),
    }


def _should_commit(kb: KB) -> bool:
    """Pre-foothold thrash signal: we have creds and a lead but have not broken in."""
    if kb.verified_accesses():
        return False
    has_creds = bool(kb.credentials)
    has_lead = any(f.status in ("suspected", "confirmed", "exploited") for f in kb.findings)
    return has_creds and has_lead


def _maybe_triage(output, name, gateway, cfg, ctx, *, now):
    """Condense an over-threshold tool output through the cheap triage model so a
    large dump does not bloat the transcript for many turns. Off unless
    strategy.triage_over_bytes > 0. Never loses data: any failure/empty result
    returns the raw output, and flags are scanned by the caller BEFORE this runs."""
    threshold = int((cfg.strategy or {}).get("triage_over_bytes", 0) or 0)
    if threshold <= 0 or gateway is None or len(output or "") <= threshold:
        return output
    # Never lossily summarize a machine dump — the bytes ARE the information for RE.
    if _is_machine_code_dump(output):
        return output
    try:
        model = cfg.model_for("triage", ctx)
        result = gateway.chat(
            model,
            [{"role": "system", "content": cfg.prompts.get("triage_system") or TRIAGE_SYSTEM},
             {"role": "user", "content": f"Tool `{name}` output:\n{output}"}],
            temperature=_temperature(cfg, "triage"), effort=_effort(cfg, "triage"), now=now,
        )
    except Exception:  # noqa: BLE001 - a triage failure must never end the run or lose data
        return output
    condensed = (result.content or "").strip()
    if not condensed:
        return output
    return f"[triaged from {len(output)} bytes]\n{condensed}"


def run(
    ctx: RunContext,
    cfg: Config,
    *,
    gateway,
    submitter,
    kb: KB | None = None,
    executor: ToolExecutor | None = None,
    now: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> RunResult:
    kb = kb or KB()
    owns_executor = executor is None
    executor = executor or ToolExecutor(ctx, kb, submitter, cfg, gateway=gateway, now=now)

    system = cfg.prompts.get("orchestrator_system") or ORCHESTRATOR_SYSTEM
    system = augment_system(system, executor)
    model = cfg.model_for("orchestrator", ctx)
    temperature = _temperature(cfg, "orchestrator")
    effort = _effort(cfg, "orchestrator")
    specs = tool_specs(cfg, delegate=True)
    replan_after = max(1, int(cfg.strategy.get("replan_after_stalls", 3) or 3))
    parallel_cap = max(1, int(cfg.strategy.get("parallel_tool_calls", 1) or 1))

    # Focus discipline — all opt-in, default off, so the plain agent is unchanged.
    max_history_turns = max(0, int(cfg.strategy.get("max_history_turns", 0) or 0))
    summarize_trimmed = bool(cfg.strategy.get("summarize_trimmed", False))
    budget_awareness = bool(cfg.strategy.get("budget_awareness", True))
    budget_below = float(cfg.strategy.get("budget_line_below_seconds", 0) or 0)
    commit_after_creds = bool(cfg.strategy.get("commit_after_creds", False))
    re_emulate_nudge = bool(cfg.strategy.get("re_emulate_nudge", False))
    re_emulate_nudge_after = max(1, int(cfg.strategy.get("re_emulate_nudge_after", 3) or 3))
    fold_self_recaps = bool(cfg.strategy.get("fold_self_recaps", False))
    recap_fold_min_chars = max(200, int(cfg.strategy.get("recap_fold_min_chars", 1200) or 1200))
    race_lock_in = bool(cfg.strategy.get("race_lock_in", False))
    race_build_nudge = bool(cfg.strategy.get("race_build_nudge", False))
    race_build_nudge_after = max(1, int(cfg.strategy.get("race_build_nudge_after", 3) or 3))
    prove_static_accept_live = bool(cfg.strategy.get("prove_static_accept_live", False))
    prove_live_nudge_after = max(1, int(cfg.strategy.get("prove_live_nudge_after", 3) or 3))
    focus_after_foothold = bool(cfg.strategy.get("focus_after_foothold", False))
    refuse_repeats = bool(cfg.strategy.get("refuse_repeats", False))
    auto_loot = bool(cfg.strategy.get("auto_loot_on_foothold", False))
    objective_aware = bool(cfg.strategy.get("objective_aware", False))
    coverage_on = bool(cfg.strategy.get("coverage_checklist", False))
    win_sequencing = bool(cfg.strategy.get("win_sequencing", False))
    objective_class = classify_objective(ctx.objective)

    # Context-aware compaction (opt-in): when context_token_budget > 0 the transcript
    # is trimmed to a fraction of the model's REAL window instead of a fixed turn count,
    # so a large-context model actually uses its window (a fixed count compacts a 128K
    # model at ~10%). The system-prompt + tool-spec overhead is measured once here.
    context_token_budget = max(0, int(cfg.strategy.get("context_token_budget", 0) or 0))
    compact_fraction = float(cfg.strategy.get("compact_at_context_fraction", 0.65) or 0.65)
    min_keep_turns = max(1, int(cfg.strategy.get("min_keep_turns", 6) or 6))
    progress_log_max = max(200, int(cfg.strategy.get("progress_log_max_chars", 2000) or 2000))
    # Fixed overhead measured in CHARS (not tokens) so it scales by the calibrated ratio
    # each turn along with the history — the ratio is corrected from real prompt_tokens.
    system_chars = _message_chars([{"role": "system", "content": system}])
    try:
        spec_chars = len(json.dumps(specs)) if specs else 0
    except (TypeError, ValueError):
        spec_chars = 0

    def _win_line() -> str | None:
        # Win-sequencing = a state-aware CURRENT-GOAL that follows the phase (nearest
        # win first). objective_aware = the simpler static win condition. Off = neither.
        if win_sequencing:
            return staged_goal(ctx.objective, kb)
        if objective_aware:
            return win_condition_text(ctx.objective)
        return None

    guard = (
        _TurnGuard(kb, refuse_repeats=refuse_repeats, focus_after_foothold=focus_after_foothold)
        if (refuse_repeats or focus_after_foothold)
        else None
    )
    looted: set[tuple[str, str]] = set()   # (session, user) pairs already swept
    last_commit_turn = -(10**9)

    history: list[dict] = []
    per_char = _TOKENS_PER_CHAR   # char->token ratio, ratcheted from real prompt_tokens
    turns = 0
    brownout_cooldowns = 0        # consecutive provider brownouts ridden out; reset by a good call
    re_static_streak = 0          # consecutive hand-disassembly turns w/o a discovery; reset by emulate/discovery
    race_static_streak = 0        # consecutive post-race-verdict turns w/o a build attempt; reset by a build
    static_accept_seen = False    # the emulator has statically ACCEPTED a frame (a hypothesis to prove live)
    static_accept_tested_live = False  # that accepted frame has since been submitted to the live daemon
    prove_streak = 0              # turns since the static accept without building the concurrent exploit
    stall_turns = 0
    last_fp = kb.fingerprint()
    last_discoveries = _discovery_count(kb)   # real facts only; robust to trim/notes/plan churn
    final_push_done = False
    reason = "teardown"

    while True:
        t = now()
        seconds_left = ctx.budget.seconds_left(t)
        if seconds_left <= 0:
            reason = "deadline"
            break

        if not final_push_done and seconds_left <= FINAL_PUSH_SECONDS:
            history.append({
                "role": "user",
                "content": "FINAL MINUTE: submit any destrier{...} flags you already have now.",
            })
            final_push_done = True

        cov_text, untried = coverage_report(kb, objective_class) if coverage_on else (None, [])
        show_budget = budget_awareness and (budget_below <= 0 or seconds_left <= budget_below)
        situation = kb.situation_digest(
            ctx, seconds_left=seconds_left, tokens=gateway.total_tokens,
            win_condition=_win_line(), foothold_focus=focus_after_foothold, coverage=cov_text,
            show_budget=show_budget,
        )

        # Compaction: keep the transcript bounded by BOTH the turn cap and the token
        # budget (whichever trims more). The turn cap always applies — a token budget set
        # for a large-window model must not disable it, or the transcript grows unbounded
        # and the agent drowns in its own dead-ends. The token budget is a FOCUS size, and
        # per_char is calibrated from real prompt_tokens so it tracks the actual tokenizer.
        # Durable facts survive in the digest, so trimming loses no state; the dropped
        # slice folds into the rolling PROGRESS LOG.
        overhead = int((system_chars + spec_chars
                        + _message_chars([{"role": "user", "content": situation}])) * per_char)
        cut = _compaction_cut_index(
            history, max_turns=max_history_turns, budget_tokens=context_token_budget,
            fraction=compact_fraction, overhead_tokens=overhead, min_keep_turns=min_keep_turns,
            per_char=per_char)
        if cut and summarize_trimmed:
            kb.progress_log = _summarize_dropped(
                history[:cut], kb.progress_log, gateway, cfg, ctx, now=now,
                max_chars=progress_log_max)
        if cut:
            history = history[cut:]

        call_messages = (
            [{"role": "system", "content": system}]
            + history
            + [{"role": "user", "content": situation}]
        )

        try:
            result = gateway.chat(
                model, call_messages, tools=specs,
                temperature=temperature, effort=effort, now=now,
            )
        except CostExhausted:
            reason = "cost_exhausted"
            break
        except Deadline:
            reason = "deadline"
            break
        except ModelNotPermitted:
            if model != ctx.default_model:
                log.warn("orchestrator model rejected; falling back to run default",
                         model=model, fallback=ctx.default_model)
                model = ctx.default_model
                continue
            reason = "gateway_error"
            break
        except UpstreamUnavailable as exc:
            # A provider brownout with budget AND time to spare. Cool down and re-enter
            # instead of ending the run on a transient hiccup (which threw away ~half a
            # run's budget). Bounded by a consecutive-cooldown cap AND the wall clock (no
            # cooldown inside the final-push window), so a dead provider can't spin forever.
            brownout_cooldowns += 1
            seconds_left = ctx.budget.seconds_left(now())
            if brownout_cooldowns > _MAX_BROWNOUT_COOLDOWNS or seconds_left <= FINAL_PUSH_SECONDS:
                log.error("gateway.brownout.giving_up",
                          cooldowns=brownout_cooldowns, detail=str(exc))
                reason = "upstream_unavailable"
                break
            cooldown = min(_BROWNOUT_COOLDOWN_SECONDS, max(0.0, seconds_left - FINAL_PUSH_SECONDS))
            log.warn("gateway.brownout.cooldown",
                     cooldowns=brownout_cooldowns, cooldown_s=round(cooldown, 1), detail=str(exc))
            sleeper(cooldown)
            continue
        except GatewayError as exc:
            log.error("gateway.error", detail=str(exc))
            reason = "gateway_error"
            break

        turns += 1
        brownout_cooldowns = 0   # a good call clears the brownout streak
        _pt = getattr(result, "prompt_tokens", 0) or 0
        if _pt:
            # Calibrate the char->token ratio from the REAL prompt size we just sent, so
            # the next trim decision tracks the actual tokenizer. Ratchets up only.
            per_char = _calibrated_per_char(
                per_char, real_tokens=_pt, chars_sent=_message_chars(call_messages))
            log.info("orchestrator.call", prompt_tokens=_pt, history_msgs=len(history),
                     per_char=round(per_char, 3))

        assistant_msg: dict = {"role": "assistant", "content": result.content}
        if result.tool_calls:
            assistant_msg["tool_calls"] = result.tool_calls
        history.append(assistant_msg)

        if result.content:
            submitter.scan(result.content)

        # Fold a pure-text self-recap (a turn spent rewriting a state summary as chat) into
        # the durable PROGRESS LOG and stub it in the transcript — its reasoning stays visible
        # in the digest without the model paying to carry/rewrite it every few turns, and the
        # stub tells the model its state is durable so it stops re-emitting. Scanning above ran
        # on the RAW content first, so a flag inside a recap is never lost. Only affects an
        # action-less turn; a normal reasoning+tool-call turn is untouched.
        if fold_self_recaps and _is_self_recap(assistant_msg, recap_fold_min_chars):
            kb.progress_log = _fold_recap(
                kb.progress_log, assistant_msg.get("content") or "", progress_log_max)
            assistant_msg["content"] = _RECAP_STUB
            log.info("recap.folded", progress_log_chars=len(kb.progress_log))

        output_budget = TurnOutputBudget(cfg)
        for tc, output in execute_tool_calls(result.tool_calls, executor, parallel_cap, guard):
            submitter.scan(output)  # scan RAW first so a flag can never be triaged away
            if race_lock_in and not kb.race_verdict:
                verdict = _extract_race_verdict(output)
                if verdict:
                    kb.race_verdict = verdict     # pin the emulator's deterministic verdict
                    log.info("race.verdict.pinned")
            if prove_static_accept_live and not static_accept_seen and not kb.race_verdict \
                    and _emitted_static_accept(output):
                static_accept_seen = True         # a static ACCEPT is a hypothesis, not a win
                log.info("static_accept.seen")
            name = parse_tool_call(tc)[0]
            content = _maybe_triage(output, name, gateway, cfg, ctx, now=now)
            log.info("tool", name=name, out_bytes=len(output))
            history.append({
                "role": "tool",
                "tool_call_id": tc.get("id", ""),
                "content": output_budget.take(content),
            })

        # The boring flag hunt, done for the model the moment a foothold lands — and again
        # each time it escalates to a NEW user in a session (keyed by (session, user)), so a
        # flag only the escalated user can read is grabbed automatically.
        if auto_loot:
            for name, user in _foothold_loot_targets(kb, executor):
                if (name, user) not in looted:
                    looted.add((name, user))
                    loot = _auto_loot(executor, name, submitter)
                    history.append({
                        "role": "user",
                        "content": (
                            f"AUTO-LOOT ran automatically on foothold session {name!r} "
                            f"as {user or '?'} (read-only). If a destrier{{...}} appears "
                            f"below it was already submitted; otherwise use these leads:\n{loot}"
                        ),
                    })

        fp = kb.fingerprint()
        made_progress = fp != last_fp
        if made_progress:
            stall_turns = 0
            last_fp = fp
        else:
            stall_turns += 1
        if stall_turns and stall_turns % replan_after == 0:
            history.append(_coverage_nudge(untried) if (coverage_on and untried) else _stall_nudge())

        # RE static-churn: hand-disassembling turn after turn without a real discovery is
        # the "read the obfuscated validator by eye" trap (a regression run: the agent said
        # "use unicorn" then ran objdump for ~200 calls). Push it to the baked emulator. An
        # actual emulation or a genuine NEW discovery resets the streak. Gate on
        # _discovery_count, NOT made_progress: made_progress fires on progress_log/notes/plan
        # churn from history-summarisation, which was silently resetting the streak so the
        # nudge never reached its threshold (a regression run: 0 nudges in 93 turns).
        if re_emulate_nudge:
            discoveries = _discovery_count(kb)
            made_discovery = discoveries != last_discoveries
            last_discoveries = discoveries
            did_static, did_emulate = _re_call_kinds(result.tool_calls)
            if did_emulate or made_discovery:
                re_static_streak = 0
            elif did_static:
                re_static_streak += 1
                if re_static_streak % re_emulate_nudge_after == 0:
                    history.append(_emulate_nudge())

        # Race-build churn: once the emulator has CONFIRMED a double-fetch race, spending turn
        # after turn NOT building the concurrent exploit (still constructing static frames,
        # stracing, hand-tracing) is the a regression run failure — it never wrote a memfd/MAP_SHARED
        # line. Push it to write the exploit. A build attempt resets the streak.
        if race_build_nudge and kb.race_verdict:
            if _did_race_build(result.tool_calls):
                race_static_streak = 0
            else:
                race_static_streak += 1
                if race_static_streak % race_build_nudge_after == 0:
                    history.append(_race_build_nudge())

        # Static-accept-must-be-proven-live: the emulator's `accepted: True` on a check-then-commit
        # VALIDATOR is false comfort — the second read that demands a different value lives in the
        # daemon handler, not the validator, so the statically-valid frame is exactly the one the live
        # daemon rejects. The model takes the accept as a win and grinds RE (regression-case/regression-case/regression-case).
        # Reframe it the moment it happens: prove the frame live; a live rejection of an accepted frame
        # IS the double-fetch -> win it concurrently with win_race. Building the exploit steps this aside.
        if prove_static_accept_live and static_accept_seen and not kb.race_verdict:
            if not _did_race_build(result.tool_calls):
                if _did_live_submit(result.tool_calls):
                    static_accept_tested_live = True
                prove_streak += 1
                if prove_streak == 1 or prove_streak % prove_live_nudge_after == 0:
                    history.append(_prove_live_nudge(static_accept_tested_live))

        if commit_after_creds and _should_commit(kb) and (turns - last_commit_turn) >= replan_after:
            history.append(_commit_nudge())
            last_commit_turn = turns

    if owns_executor:
        executor.close()
    captured = len(getattr(submitter, "captured", ()) or ())
    return RunResult(reason=reason, turns=turns, flags_captured=captured)


def _temperature(cfg: Config, role: str) -> float | None:
    temps = cfg.sampling.get("temperature", {}) if isinstance(cfg.sampling, dict) else {}
    if isinstance(temps, dict) and role in temps:
        try:
            return float(temps[role])
        except (TypeError, ValueError):
            return None
    return None


def _effort(cfg: Config, role: str) -> str | None:
    eff = cfg.sampling.get("effort", {}) if isinstance(cfg.sampling, dict) else {}
    if isinstance(eff, dict) and eff.get(role):
        return str(eff[role])
    return None

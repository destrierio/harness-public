"""The Knowledge Base: the single structured source of truth for a run.

Everything the agent learns lands here as typed facts, and every orchestrator turn
is handed a compact SITUATION digest rendered from it, so the brain reads current
state instead of re-deriving it from a long, compacted transcript. `fingerprint`
lets the loop notice a turn that changed nothing (an anti-stall signal, never a
run limiter).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

# Rank order for findings in the digest: acted-on and confirmed leads first.
_STATUS_RANK = {"exploited": 0, "confirmed": 1, "suspected": 2, "dead": 3}

# Objective classes, checked in this order. The point is not a taxonomy but pursuing
# the matching win condition: a foothold objective is won by a shell, not a flag file.
_OBJECTIVE_KEYWORDS = (
    ("pwn", ("binary", "pwn", "buffer overflow", "rop chain", "heap", "shellcode",
             "ret2", "format string", "stack overflow", "exploit the binary")),
    ("foothold", ("foothold", "service-user", "service user", "initial access",
                  "gain access", "get access", "get a shell", "get user", "user shell",
                  "shell as", "log in as", "logon as", "become ", "as the ", "-user",
                  "www-data", "authenticated user")),
    ("privesc", ("root", "administrator", "privilege", "escalate", "privesc",
                 "superuser", "system account", "domain admin")),
    ("flag_file", ("flag", "loot", "read the", "capture")),
)

_WIN_CONDITION = {
    "foothold": (
        "OBJECTIVE TYPE: FOOTHOLD. WIN = an interactive session (shell) on the target "
        "as the user the objective names. Drive to that shell first — enable telnet/ssh "
        "via a config/CGI write, a CVE/command-injection reverse shell, or reused "
        "credentials — and confirm it with `id`. Read/submit the flag only AFTER you "
        "hold the shell; do not spend the run hunting flag files."
    ),
    "privesc": (
        "OBJECTIVE TYPE: PRIVILEGE ESCALATION. WIN = escalate the current foothold to the "
        "required privilege, then read and submit the flag. No foothold yet? Get one first."
    ),
    "flag_file": (
        "OBJECTIVE TYPE: FLAG READ. WIN = reading a destrier{...} value and submitting it. "
        "Take the shortest path — a file read (LFI/traversal) or a shell, whichever is closer."
    ),
    "pwn": (
        "OBJECTIVE TYPE: BINARY EXPLOITATION. WIN = a working exploit that leaks/reads the "
        "flag or pops a shell. fetch_artifact the binary, triage, and develop in python_exec "
        "with pwntools; prove locally, then point it at the live service."
    ),
}


def classify_objective(objective: str) -> str:
    """Bucket the objective so the harness can surface the matching win condition.
    Generic and keyword-based — never tuned to a specific box."""
    text = (objective or "").lower()
    for label, keywords in _OBJECTIVE_KEYWORDS:
        if any(k in text for k in keywords):
            return label
    return "generic"


def win_condition_text(objective: str) -> str | None:
    """The one-line win condition for an objective, or None when it is generic."""
    return _WIN_CONDITION.get(classify_objective(objective))


_PRIV_RANK = {"administrator": 3, "root": 3, "user": 1, "": 0}


def staged_goal(objective: str, kb: "KB") -> str | None:
    """The CURRENT-stage goal given the objective AND current access — so the agent
    pursues the NEAREST win first instead of jumping to the hard target early
    (LEARNINGS: 'half the wandering was it jumping to the hard target too early'). A
    privilege-gated flag is unreachable without a foothold, so before one exists the
    goal is always the foothold, whatever the ultimate objective."""
    cls = classify_objective(objective)
    if cls == "pwn":
        return _WIN_CONDITION["pwn"]
    has_foothold = bool(kb.verified_accesses())
    if not has_foothold:
        if cls == "privesc":
            return (
                "CURRENT GOAL (stage 1 of 2): get a FOOTHOLD first — a user shell. The flag "
                "is privilege-gated and unreachable until you are in, so do NOT hunt the "
                "root/admin flag yet. Win the shell (default creds, a CVE, an injection), "
                "then escalate."
            )
        return (
            "CURRENT GOAL: gain access — the interactive shell / foothold the objective names "
            "— before hunting flag files. The nearest win is the way in; drive one exploit to "
            "a session and confirm it with `id`."
        )
    priv = max((a.privilege or "" for a in kb.verified_accesses()), key=lambda p: _PRIV_RANK.get(p, 0))
    if cls == "privesc" and _PRIV_RANK.get(priv, 0) < 3:
        return (
            "CURRENT GOAL (stage 2 of 2): you HAVE a foothold — now escalate to root/admin and "
            "read the flag. Work sudo -l, SUID/SGID, capabilities, cron, kernel, writable "
            "root-run paths, and credential reuse; delegate to the privesc specialist."
        )
    return (
        "CURRENT GOAL: you HOLD the access the objective needs — read and submit the flag from "
        "this shell now, then look for any further flag or host."
    )


@dataclass
class Service:
    host: str
    port: int
    proto: str = "tcp"
    product: str = ""
    version: str = ""
    notes: str = ""


@dataclass
class Finding:
    host: str
    cls: str
    status: str  # suspected | confirmed | exploited | dead
    service: str = ""
    evidence: str = ""
    next_action: str = ""


@dataclass
class Credential:
    value: str
    where_found: str = ""
    works_on: str = ""
    privilege: str = ""


@dataclass
class Access:
    host: str
    session: str
    user: str = ""
    privilege: str = ""  # user | root | administrator
    how: str = ""
    verified: bool = True  # False = recorded but not yet confirmed with `id` (see verify_access)


@dataclass
class Host:
    address: str
    hostname: str = ""
    reachable_via: str = "direct"  # "direct" or a foothold/pivot session name
    notes: str = ""


@dataclass
class FlagRecord:
    value: str
    host: str = ""
    privilege: str = ""
    submitted: bool = False
    captured: bool = False


@dataclass
class Artifact:
    name: str
    path: str
    sha256: str = ""
    source: str = ""


@dataclass
class PlanStep:
    goal: str = ""
    status: str = "open"  # open | active | done | abandoned
    note: str = ""


@dataclass
class KB:
    phase: str = "recon"
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    accesses: list[Access] = field(default_factory=list)
    flags: list[FlagRecord] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    dead_ends: list[str] = field(default_factory=list)
    plan: list[PlanStep] = field(default_factory=list)
    progress_log: str = ""
    notes: str = ""
    race_verdict: str = ""   # a deterministic double-fetch/TOCTOU verdict from re_emulate, pinned
    hosts: list[Host] = field(default_factory=list)

    def record_service(self, **kw) -> None:
        self.services.append(Service(**kw))

    def record_finding(self, **kw) -> None:
        self.findings.append(Finding(**kw))

    def record_credential(self, **kw) -> None:
        self.credentials.append(Credential(**kw))

    def record_access(self, **kw) -> None:
        self.accesses.append(Access(**kw))

    def verified_accesses(self) -> list["Access"]:
        """Accesses confirmed to be real shells — the canonical 'held foothold' set.
        An unverified (possibly hallucinated) access must not trip focus behaviour."""
        return [a for a in self.accesses if a.verified]

    def record_host(self, **kw) -> None:
        self.hosts.append(Host(**kw))

    def record_flag(self, **kw) -> None:
        self.flags.append(FlagRecord(**kw))

    def record_artifact(self, **kw) -> None:
        self.artifacts.append(Artifact(**kw))

    def mark_dead(self, what: str) -> None:
        self.dead_ends.append(what)

    def set_notes(self, text: str) -> None:
        """Replace the model's durable scratchpad. Byte-level RE state (offsets, opcode/
        state tables) and VERIFIED-vs-PLANTED verdicts have no typed field of their own;
        they live here so a transcript trim never loses them and the model stops
        re-emitting them as chat. The model rewrites it whole."""
        self.notes = text or ""

    def set_plan(self, steps) -> None:
        """Replace the plan with a fresh ranked list (the model rewrites it whole).
        Coerces loose dicts; never raises on bad input — a tool error is data."""
        out: list[PlanStep] = []
        for s in steps or []:
            if isinstance(s, dict):
                out.append(PlanStep(
                    goal=str(s.get("goal", "")),
                    status=str(s.get("status", "open")) or "open",
                    note=str(s.get("note", "")),
                ))
            elif isinstance(s, str):
                out.append(PlanStep(goal=s))
        self.plan = out

    def ranked_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: _STATUS_RANK.get(f.status, 9))

    def fingerprint(self) -> str:
        state = {
            "phase": self.phase,
            "services": [asdict(s) for s in self.services],
            "findings": [asdict(f) for f in self.findings],
            "credentials": [asdict(c) for c in self.credentials],
            "accesses": [asdict(a) for a in self.accesses],
            "flags": [asdict(fl) for fl in self.flags],
            "artifacts": [asdict(a) for a in self.artifacts],
            "dead_ends": list(self.dead_ends),
            "plan": [asdict(p) for p in self.plan],
            "progress_log": self.progress_log,
            "notes": self.notes,
            "race_verdict": self.race_verdict,
            "hosts": [asdict(h) for h in self.hosts],
        }
        blob = json.dumps(state, sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()

    def situation_digest(
        self,
        ctx,
        *,
        seconds_left: float,
        tokens: int,
        win_condition: str | None = None,
        foothold_focus: bool = False,
        coverage: str | None = None,
        show_budget: bool = True,
    ) -> str:
        lines: list[str] = ["=== SITUATION ==="]
        held = self.verified_accesses()
        if foothold_focus and held:
            a = held[0]
            lines.append(
                f"*** FOOTHOLD MODE: you HAVE a shell on {a.host} as {a.user or '?'} "
                f"[{a.privilege or '?'}] via session '{a.session or '?'}'. Do NOT run new "
                f"port scans or content discovery. FIRST secure the easy flag: `cat "
                f"/home/*/user.txt /root/root.txt` and any home *.txt — grab it BEFORE any "
                f"reverse-engineering. If you su/escalate to another user, record_access "
                f"that shell so the loot re-runs there. Then escalate for a gated flag. ***"
            )
        lines.append(f"Objective: {ctx.objective}")
        if win_condition:
            lines.append(win_condition)
        if self.race_verdict:
            # A tool-confirmed double-fetch race, pinned near the top so noisy contradicting
            # evidence (a broken local lab, an isolated single-threaded emulation) cannot argue
            # it away. Emulation is single-threaded over static memory and CANNOT solve a race;
            # do not let a "construct a static frame" theory reappear and override this.
            lines.append(
                "*** CONFIRMED BY EMULATOR — a deterministic tool verdict; do NOT override it "
                "with static-frame theories or noisy local-lab results: ***")
            lines.append(self.race_verdict)
            lines.append(
                "  ACT ON THIS: run the baked driver `python3 -m harness.win_race` "
                "(--sock/--submit-hex/--field-offset/--preview/--commit/--success) — it does the "
                "CONCURRENT flip for you: shared page (memfd_create + mmap MAP_SHARED), submit "
                "(fd via SCM_RIGHTS), flip the field between the required values from a background "
                "writer, resubmit until it accepts. No single static buffer can pass a "
                "check-then-commit gate; do not hand-write the concurrency. consult_skill "
                "'race-condition-toctou'.")
        lines.append(f"Phase: {self.phase}")
        if ctx.self_ip:
            lines.append(f"Our IP (LHOST for reverse shells): {ctx.self_ip}")
        targets = ", ".join(
            t.hostname + (f" ({t.address})" if t.address else "") for t in ctx.targets
        )
        lines.append(f"Targets: {targets or 'none listed — resolve from objective'}")

        if self.plan:
            lines.append("PLAN (your ranked hypotheses — keep current with update_plan):")
            for s in self.plan:
                note = f" — {s.note}" if s.note else ""
                lines.append(f"  [{s.status}] {s.goal}{note}".rstrip())

        if self.notes:
            lines.append(
                "NOTES (your durable scratchpad — persists every turn; keep byte layouts, "
                "offsets, opcode/state tables, and which values are VERIFIED vs PLANTED "
                "here, and maintain it with update_notes):"
            )
            lines.append(self.notes)

        if self.progress_log:
            lines.append("PROGRESS LOG (older turns, summarized):")
            lines.append(f"  {self.progress_log}")

        if self.services:
            lines.append("Services:")
            for s in self.services:
                banner = " ".join(x for x in (s.product, s.version) if x)
                lines.append(f"  - {s.host}:{s.port}/{s.proto} {banner}".rstrip())

        if self.findings:
            lines.append("Findings (best leads first):")
            for f in self.ranked_findings():
                tail = f" -> {f.next_action}" if f.next_action else ""
                lines.append(f"  - [{f.status}] {f.host} {f.service} {f.cls}{tail}")

        if coverage:
            lines.append(coverage)

        if self.credentials:
            lines.append("Credentials:")
            for c in self.credentials:
                where = f" (on {c.works_on})" if c.works_on else ""
                lines.append(f"  - {c.value}{where}")

        if self.accesses:
            lines.append("Footholds:")
            for a in self.accesses:
                tag = "" if a.verified else " [UNVERIFIED — prove it with id in the session]"
                lines.append(f"  - {a.host} as {a.user or '?'} [{a.privilege or '?'}] via {a.how}{tag}")

        if self.hosts:
            lines.append("Network:")
            for h in self.hosts:
                name = f" {h.hostname}" if h.hostname else ""
                lines.append(f"  - {h.address}{name} (via {h.reachable_via})".rstrip())

        captured = [fl.value for fl in self.flags if fl.captured]
        if captured:
            lines.append(f"Flags captured: {', '.join(captured)}")

        if self.dead_ends:
            lines.append("Dead ends (do not retry):")
            for d in self.dead_ends[-12:]:
                lines.append(f"  - {d}")

        if self.artifacts:
            lines.append("Artifacts in /workspace:")
            for a in self.artifacts:
                lines.append(f"  - {a.name} ({a.path})")

        if show_budget:
            lines.append(f"Budget: {int(seconds_left)}s wall-clock left, ~{tokens} tokens used.")
        return "\n".join(lines)

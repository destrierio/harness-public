"""Attack-surface coverage: a derived, advisory checklist of which standard vectors
have been tried on the active surface, so a stalled agent is pointed at the best
UNTRIED vector instead of wandering. Generic and adaptive — the vector set is keyed
to the phase (way in vs. way up) and service kind, never to a specific box. It reads
existing KB findings (matched to a canonical vector by their class text); nothing new
is recorded. Advisory only: it names what's untried, it never forces the list.
"""
from __future__ import annotations

# Canonical vectors per surface, ordered simplest / highest-yield first so the
# "untried" list is already a sensible try-next order.
WEB_VECTORS = [
    "default-creds", "known-cve", "lfi-rfi", "sqli", "command-injection",
    "auth-bypass", "file-upload", "ssti", "xxe", "ssrf", "deserialization",
    "content-discovery",
]
AUTH_VECTORS = ["default-creds", "credential-reuse", "anon-access", "credential-bruteforce", "known-cve"]
HOST_VECTORS = ["sudo", "suid-sgid", "capabilities", "cron", "credential-reuse", "writable-root-path", "kernel-exploit"]
PWN_VECTORS = ["triage-checksec", "stack-overflow", "format-string", "heap-corruption", "rop-ret2libc"]

# canonical vector -> substrings that, seen in a finding's class text, map to it
_ALIASES: dict[str, tuple[str, ...]] = {
    "default-creds": ("default cred", "weak cred", "default password", "default login", "admin:admin"),
    "known-cve": ("cve", "known-cve", "known cve", "exploit-db", "edb-", "metasploit", "msf module"),
    "lfi-rfi": ("lfi", "rfi", "file inclusion", "path traversal", "directory traversal", "arbitrary file read", "file read", "../"),
    "sqli": ("sqli", "sql injection", "sql inj", "union select", "blind sql"),
    "command-injection": ("command inj", "cmd inj", "os command", "command execution", "rce", "remote code", "code exec", "shell inject"),
    "auth-bypass": ("auth bypass", "authentication bypass", "authz", "idor", "broken auth", "jwt", "cookie forg", "session forg"),
    "file-upload": ("file upload", "unrestricted upload", "webshell upload", "arbitrary upload"),
    "ssti": ("ssti", "template inj", "server-side template"),
    "xxe": ("xxe", "xml external", "xml entity"),
    "ssrf": ("ssrf", "server-side request"),
    "deserialization": ("deserial", "insecure deserialization", "pickle", "gadget chain", "java serial"),
    "content-discovery": ("content discovery", "dir brute", "directory listing", "hidden endpoint", "backup file"),
    "sudo": ("sudo",),
    "suid-sgid": ("suid", "sgid", "setuid"),
    "capabilities": ("capabilit", "cap_"),
    "cron": ("cron", "scheduled task"),
    "credential-reuse": ("reuse", "reused cred", "password reuse"),
    "writable-root-path": ("writable", "world-writable", "path hijack", "ld_preload", "ld_library", "service file", "unit file"),
    "kernel-exploit": ("kernel", "dirtycow", "dirty pipe", "pwnkit", "overlayfs", "dirtypipe"),
    "anon-access": ("anon", "anonymous", "null session", "guest login"),
    "credential-bruteforce": ("brute", "hydra", "password spray", "wordlist"),
}

_STATUS_RANK = {"untried": 0, "dead": 1, "suspected": 2, "confirmed": 3, "exploited": 4}

_WEB_PORTS = {80, 443, 8080, 8000, 8443, 8888, 3000, 5000, 8081, 8090}
_WEB_WORDS = ("http", "nginx", "apache", "boa", "lighttpd", "uhttpd", "goahead", "tomcat", "iis", "web")
_AUTH_PORTS = {22, 21, 23, 445, 139, 3389, 3306, 5432, 6379, 1433, 27017, 5900}
_AUTH_WORDS = ("ssh", "ftp", "telnet", "smb", "rdp", "mysql", "postgres", "redis", "mssql", "mongo", "vnc")


def _service_kinds(services) -> set[str]:
    kinds: set[str] = set()
    for s in services:
        blob = f"{getattr(s, 'product', '')} {getattr(s, 'version', '')} {getattr(s, 'notes', '')}".lower()
        port = getattr(s, "port", 0) or 0
        if port in _WEB_PORTS or any(w in blob for w in _WEB_WORDS):
            kinds.add("web")
        if port in _AUTH_PORTS or any(w in blob for w in _AUTH_WORDS):
            kinds.add("auth")
    return kinds


def _match_vectors(cls_text: str) -> list[str]:
    text = (cls_text or "").lower()
    return [vector for vector, aliases in _ALIASES.items() if any(a in text for a in aliases)]


def _status_by_vector(findings, vectors: list[str]) -> dict[str, str]:
    status = {v: "untried" for v in vectors}
    allowed = set(vectors)
    for f in findings:
        f_status = getattr(f, "status", "") or "untried"
        for vector in _match_vectors(getattr(f, "cls", "")):
            if vector in allowed and _STATUS_RANK.get(f_status, 0) > _STATUS_RANK.get(status[vector], 0):
                status[vector] = f_status
    return status


def coverage_report(kb, objective_class: str) -> tuple[str | None, list[str]]:
    """Return (digest_text, untried_vectors) for the currently active surface, or
    (None, []) when a checklist is not yet useful (bare recon, no services). The
    active surface follows the phase: host/privesc once a foothold is held, otherwise
    the way in (web/auth) or the binary for a pwn objective."""
    if kb.verified_accesses():
        surface, vectors = "host / privilege-escalation", HOST_VECTORS
    elif objective_class == "pwn":
        surface, vectors = "binary", PWN_VECTORS
    elif kb.services:
        kinds = _service_kinds(kb.services)
        if "web" in kinds:
            surface, vectors = "web entry", WEB_VECTORS
        elif "auth" in kinds:
            surface, vectors = "auth-service entry", AUTH_VECTORS
        else:
            surface, vectors = "entry", WEB_VECTORS
    else:
        return (None, [])  # nothing listening yet — recon first, no checklist to show

    status = _status_by_vector(kb.findings, vectors)
    done = [v for v in vectors if status[v] in ("confirmed", "exploited")]
    inprog = [v for v in vectors if status[v] == "suspected"]
    dead = [v for v in vectors if status[v] == "dead"]
    untried = [v for v in vectors if status[v] == "untried"]

    lines = [f"Coverage — {surface} (advisory: try the best UNTRIED next; don't force the whole list):"]
    if done:
        lines.append("  landed: " + ", ".join(done))
    if inprog:
        lines.append("  in progress: " + ", ".join(inprog))
    if dead:
        lines.append("  dead (don't retry): " + ", ".join(dead))
    lines.append("  UNTRIED: " + (", ".join(untried) if untried else "(none — pivot to another service/host)"))
    return ("\n".join(lines), untried)

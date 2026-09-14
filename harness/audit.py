"""Build-time capability gate: the promise=mechanism enforcer.

Turns "discover the missing tool by failing inside a sealed cell" into "fail the
build/test". Two tiers:

  * offline (runs in `make test`, no Docker): every attack vector the coverage
    checklist can name maps to a real skill, and no skill tells the model to reach
    for a tool the image does not bake (the sentinel lint).
  * in-image (gated, needs the built image): every tool we PROMISE is on $PATH.
    See tests/e2e/test_image_tools.py.

The lists here are the single source of truth for "what a skill is allowed to
assume". Add a tool to a skill => bake it and list it here, or the gate fails.
"""
from __future__ import annotations

import glob
import os

from .coverage import AUTH_VECTORS, HOST_VECTORS, PWN_VECTORS, WEB_VECTORS

# Tools the harness image guarantees on $PATH — baked by kali-linux-headless or by
# the harness Dockerfile (linpeas/pspy/32-bit toolchain). The in-image probe
# asserts every one of these resolves.
PROMISED_TOOLS = (
    "nmap", "gobuster", "sqlmap", "hydra", "john", "smbclient", "psql",
    "searchsploit", "msfconsole", "msfvenom",
    "gdb", "objdump", "ropper", "ROPgadget", "one_gadget", "patchelf",
    "chromium", "python3", "ruby", "gcc",
    "linpeas.sh", "pspy",
    "radare2", "binwalk", "chisel", "proxychains", "unsquashfs", "debugfs",
    "qemu-x86_64-static", "qemu-aarch64-static",
)

# Python modules the RE/pwn recipes drive through python_exec. The gate covers
# these too, not only $PATH tools: a missing wheel (unicorn's manylinux build, say)
# should fail the build, not surface as an ImportError mid-run inside a sealed cell.
# pwntools pulls capstone transitively; unicorn is the parser-emulation add.
PROMISED_PYMODULES = ("pwn", "unicorn", "capstone")

# Sentinels: tools easy to *assume* present but often absent — the class that bit
# us (a skill said "use linpeas" on an image that never baked it). BACKED ones the
# image really provides; a skill body naming any sentinel NOT in BACKED fails the
# offline gate.
BACKED_SENTINELS = ("linpeas", "pspy", "searchsploit", "metasploit", "msfconsole", "msfvenom", "chisel", "binwalk", "radare2")
UNBACKED_SENTINELS = ("ligolo",)  # socat + chisel ARE baked (verified in-image)
SENTINEL_TOOLS = BACKED_SENTINELS + UNBACKED_SENTINELS

# Every coverage vector -> the skill that teaches it. A vector with no real skill
# means the stall nudge points the model at a door with no key behind it.
VECTOR_SKILL = {
    # web
    "default-creds": "auth-bypass-default-creds",
    "known-cve": "known-cve-exploitation",
    "lfi-rfi": "lfi-rfi",
    "sqli": "sqli",
    "command-injection": "command-injection",
    "auth-bypass": "auth-bypass-default-creds",
    "file-upload": "file-upload",
    "ssti": "ssti",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "deserialization": "deserialization",
    "content-discovery": "web-content-discovery",
    # auth-service
    "credential-reuse": "credential-hunting",
    "anon-access": "service-enumeration",
    "credential-bruteforce": "credential-hunting",
    # host / privesc
    "sudo": "linux-privesc",
    "suid-sgid": "linux-privesc",
    "capabilities": "linux-privesc",
    "cron": "linux-privesc",
    "writable-root-path": "linux-privesc",
    "kernel-exploit": "linux-privesc",
    # pwn
    "triage-checksec": "pwn-triage",
    "stack-overflow": "ret2libc",
    "format-string": "format-string",
    "heap-corruption": "heap-tcache",
    "rop-ret2libc": "ret2libc",
}


# Keep event-specific denylist values outside version control.
# Organizers may supply their own values in a private validation environment.
STRIPPED_SECRETS: tuple[str, ...] = ()


def skills_dir(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("SKILLS_DIR")
    if env:
        return env
    for candidate in ("skills", os.path.join(os.path.dirname(__file__), "..", "skills")):
        if os.path.isdir(candidate):
            return candidate
    return "skills"


def _skill_exists(name: str, sdir: str) -> bool:
    return os.path.isfile(os.path.join(sdir, f"{name}.md"))


def sentinel_violations(sdir: str | None = None) -> list[tuple[str, str]]:
    """(skill_file, tool) for every skill body that names a sentinel tool the image
    does not bake. Empty list = the playbooks only reach for tools that are present."""
    sdir = skills_dir(sdir)
    out: list[tuple[str, str]] = []
    for path in sorted(glob.glob(os.path.join(sdir, "*.md"))):
        try:
            text = open(path, encoding="utf-8").read().lower()
        except OSError:
            continue
        name = os.path.basename(path)
        for tool in SENTINEL_TOOLS:
            if tool in text and tool not in BACKED_SENTINELS:
                out.append((name, tool))
    return out


def coverage_vector_skill_gaps(sdir: str | None = None) -> list[str]:
    """Vectors (from coverage.py) with no mapping here, or a mapping to a missing
    skill file. Empty list = every 'try this next' nudge has a playbook behind it."""
    sdir = skills_dir(sdir)
    gaps: list[str] = []
    for vector in {*WEB_VECTORS, *AUTH_VECTORS, *HOST_VECTORS, *PWN_VECTORS}:
        skill = VECTOR_SKILL.get(vector)
        if skill is None:
            gaps.append(f"{vector}: no skill mapping")
        elif not _skill_exists(skill, sdir):
            gaps.append(f"{vector}: maps to missing skill {skill!r}")
    return sorted(gaps)


def corpus_dir(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("CVE_CORPUS_DIR")
    if env:
        return env
    for candidate in ("cve-corpus", os.path.join(os.path.dirname(__file__), "..", "cve-corpus")):
        if os.path.isdir(candidate):
            return candidate
    return "cve-corpus"


def corpus_entry_count(cdir: str | None = None) -> int:
    """How many CVE leads the offline corpus carries (one `## CVE...` heading each)."""
    cdir = corpus_dir(cdir)
    total = 0
    for path in glob.glob(os.path.join(cdir, "*.md")):
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            continue
        total += sum(1 for line in text.splitlines() if line.startswith("## CVE"))
    return total


def answer_key_leaks(sdir: str | None = None, cdir: str | None = None) -> list[tuple[str, str]]:
    """(file, secret) for every stripped box secret found in a skill or corpus file.
    Empty list = the advisory-level material stayed advisory (no baked answer keys)."""
    out: list[tuple[str, str]] = []
    for root in (skills_dir(sdir), corpus_dir(cdir)):
        for path in sorted(glob.glob(os.path.join(root, "*.md"))):
            try:
                text = open(path, encoding="utf-8").read()
            except OSError:
                continue
            for secret in STRIPPED_SECRETS:
                if secret in text:
                    out.append((os.path.relpath(path), secret))
    return out


def answer_constant_leaks(constants, roots=None) -> list[tuple[str, str]]:
    """(file, constant) for every banned box-answer constant found in shipped code or skills.

    `constants` is passed IN by the caller (they live in a test, never in a shipped file), so
    this can scan harness code too without flagging its own denylist. Defaults to every
    harness/*.py and skills/*.md. This closes the hole that let a real mode/status constant sit
    in a baked tool's docstring example, invisible to the skills-only `answer_key_leaks` gate:
    a baked exploit driver can leak the answer just as a skill can — either must fail the build.
    """
    lits = [str(c).lower() for c in constants]
    if roots is None:
        here = os.path.dirname(__file__)
        roots = sorted(glob.glob(os.path.join(here, "*.py")))
        roots += sorted(glob.glob(os.path.join(skills_dir(), "*.md")))
    out: list[tuple[str, str]] = []
    for path in roots:
        try:
            text = open(path, encoding="utf-8").read().lower()
        except OSError:
            continue
        for lit in lits:
            if lit in text:
                out.append((os.path.relpath(path), lit))
    return out


def missing_promised_tools(which=None) -> list[str]:
    """Promised tools not resolvable on $PATH. Meaningful only when run inside the
    built image (or against it). `which` defaults to shutil.which."""
    if which is None:
        import shutil
        which = shutil.which
    return [t for t in PROMISED_TOOLS if which(t) is None]


def missing_promised_pymodules(importer=None) -> list[str]:
    """Promised python modules that fail to import. Meaningful only inside the built
    image (or against its interpreter). `importer` defaults to importlib.import_module
    and is injectable for tests."""
    if importer is None:
        import importlib
        importer = importlib.import_module
    missing: list[str] = []
    for mod in PROMISED_PYMODULES:
        try:
            importer(mod)
        except Exception:  # noqa: BLE001 — any import failure means it is not usable
            missing.append(mod)
    return missing

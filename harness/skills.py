"""The skills library: on-demand markdown playbooks. Knowledge stays out of the
base prompt until the agent calls consult_skill, keeping context lean. Each file in
skills/ has YAML frontmatter (name, when, tools, phase) and a model-actionable body
(method + exact commands + pitfalls). The library is the primary configurability
surface later: users add or edit playbooks to teach new techniques without code.
"""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field

import yaml


@dataclass
class Skill:
    name: str
    when: str = ""
    tools: list = field(default_factory=list)
    phase: str = ""
    body: str = ""
    path: str = ""


class SkillLibrary:
    def __init__(self, skills: list[Skill]) -> None:
        self._skills = {s.name: s for s in skills}

    @classmethod
    def load(cls, path: str | None = None) -> "SkillLibrary":
        path = path or _default_dir()
        skills: list[Skill] = []
        if path and os.path.isdir(path):
            for filepath in sorted(glob.glob(os.path.join(path, "*.md"))):
                skill = _parse(filepath)
                if skill:
                    skills.append(skill)
        return cls(skills)

    def names(self) -> list[str]:
        return sorted(self._skills)

    def get(self, name: str) -> Skill | None:
        key = (name or "").strip().lower()
        candidates = {key, key.replace(" ", "-"), key.removesuffix(".md")}
        for skill_name, skill in self._skills.items():
            if skill_name.lower() in candidates:
                return skill
        return None

    def index(self) -> str:
        if not self._skills:
            return "(no skills loaded)"
        return "\n".join(f"- {n}: {s.when}".rstrip(": ") for n, s in sorted(self._skills.items()))


def _parse(filepath: str) -> Skill | None:
    try:
        with open(filepath, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    meta: dict = {}
    body = text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                meta = yaml.safe_load(parts[1]) or {}
            except yaml.YAMLError:
                meta = {}
            body = parts[2].strip()
    if not isinstance(meta, dict):
        meta = {}
    name = meta.get("name") or os.path.splitext(os.path.basename(filepath))[0]
    return Skill(
        name=str(name),
        when=str(meta.get("when", "")),
        tools=meta.get("tools", []) or [],
        phase=str(meta.get("phase", "")),
        body=body,
        path=filepath,
    )


def _default_dir() -> str | None:
    env = os.environ.get("SKILLS_DIR")
    if env:
        return env
    candidates = ["skills", os.path.join(os.path.dirname(__file__), "..", "skills")]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return None


def augment_system(base: str, executor) -> str:
    """Append the skills index to a system prompt so the agent knows what it can
    consult. Falls back gracefully if the library cannot be loaded."""
    try:
        index = executor.skills().index()
    except Exception:  # noqa: BLE001
        index = "(no skills loaded)"
    return (
        base
        + "\n\n## Available skills (call consult_skill with the exact name for "
        "step-by-step method and exact commands)\n"
        + index
    )

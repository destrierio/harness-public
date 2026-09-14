"""Parse config.yaml into a Config, and resolve model roles against the run's
permitted set. The core guarantee: no config can break a run. Loading never raises,
and a role naming a forbidden or unknown model falls back to the run default.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .runtime import RunContext


@dataclass
class Config:
    models: dict[str, object]
    prompts: dict[str, str]
    strategy: dict[str, object]
    sampling: dict[str, object]
    tools: dict[str, object]
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | None, ctx: RunContext) -> "Config":
        warnings: list[str] = []
        data: dict = {}
        if path:
            try:
                with open(path, encoding="utf-8") as fh:
                    loaded = yaml.safe_load(fh)
                if loaded is None:
                    loaded = {}
                if not isinstance(loaded, dict):
                    raise ValueError("config root is not a mapping")
                data = loaded
            except FileNotFoundError:
                warnings.append(f"config file not found at {path}; using defaults")
            except (yaml.YAMLError, ValueError, OSError) as exc:
                warnings.append(f"could not parse {path} ({exc}); using defaults")

        def section(key: str) -> dict:
            val = data.get(key, {})
            return val if isinstance(val, dict) else {}

        return cls(
            models=section("models"),
            prompts=section("prompts"),
            strategy=section("strategy"),
            sampling=section("sampling"),
            tools=section("tools"),
            warnings=warnings,
        )

    def model_for(self, role: str, ctx: RunContext) -> str:
        """Resolve a role to a permitted model. `models.<role>` may be a single name
        or a PRIORITY LIST — the first PERMITTED entry wins, so one config runs on a
        single-model event (every unpermitted name is skipped and it collapses onto
        the default) and a multi-model event (it reaches for the strong model).
        'auto'/'' = the run default, which always works. Nothing here breaks a run."""
        requested = self.models.get(role, "auto")
        candidates = requested if isinstance(requested, (list, tuple)) else [requested]
        tried: list[str] = []
        for cand in candidates:
            name = str(cand or "").strip()
            if name in ("", "auto"):
                return ctx.default_model
            if name in ctx.permitted_models:
                return name
            tried.append(name)
        if tried:
            self.warnings.append(
                f"no permitted model for role {role!r} among {tried}; "
                f"using {ctx.default_model!r}"
            )
        return ctx.default_model

"""Parse the sealed-cell contract (injected env + task descriptor) into a RunContext.

Every fact here is delivered by the platform. Only four vars are truly required to
run at all; the rest degrade to sensible values so a partial environment (local
testing) still boots.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Budget:
    wall_clock_seconds: float
    max_cost_micro_usd: int | None
    started_monotonic: float

    def seconds_left(self, now: float) -> float:
        return self.wall_clock_seconds - (now - self.started_monotonic)

    def fraction_used(self, now: float) -> float:
        if self.wall_clock_seconds <= 0:
            return 1.0
        used = (now - self.started_monotonic) / self.wall_clock_seconds
        return max(0.0, min(1.0, used))


@dataclass(frozen=True)
class Target:
    hostname: str
    address: str | None = None
    network: str | None = None


@dataclass(frozen=True)
class RunContext:
    run_id: str
    agent_token: str
    provider_base_url: str
    event_endpoint: str
    flag_endpoint: str
    default_model: str
    permitted_models: tuple[str, ...]
    objective: str
    self_ip: str | None
    targets: tuple[Target, ...]
    budget: Budget

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        task: dict | None,
        *,
        now: float,
    ) -> "RunContext":
        task = task or {}

        def required(name: str) -> str:
            val = env.get(name, "").strip()
            if not val:
                raise ValueError(f"missing required environment variable {name}")
            return val

        run_id = required("BOXR_RUN_ID")
        agent_token = required("BOXR_AGENT_TOKEN")
        provider_base_url = required("BOXR_PROVIDER_BASE_URL")
        flag_endpoint = required("BOXR_FLAG_ENDPOINT")
        event_endpoint = env.get("BOXR_EVENT_ENDPOINT", "").strip()

        default_model = env.get("BOXR_MODEL", "").strip()
        permitted_raw = env.get("BOXR_MODELS", "").strip()
        permitted = tuple(
            m.strip() for m in permitted_raw.split(",") if m.strip()
        )
        if not permitted:
            permitted = (default_model,) if default_model else ()
        if not default_model and permitted:
            default_model = permitted[0]

        objective = str(task.get("objective") or env.get("BOXR_OBJECTIVE", "")).strip()

        self_ip = None
        self_block = task.get("self")
        if isinstance(self_block, Mapping):
            self_ip = self_block.get("ip")

        targets = tuple(
            Target(
                hostname=t.get("hostname", ""),
                address=t.get("address"),
                network=t.get("network"),
            )
            for t in task.get("targets", [])
            if isinstance(t, Mapping) and t.get("hostname")
        )

        wall = float(env.get("BOXR_MAX_WALL_CLOCK_SEC", "0") or 0)
        cost_raw = env.get("BOXR_MAX_COST_MICRO_USD", "").strip()
        max_cost = int(cost_raw) if cost_raw else None
        budget = Budget(
            wall_clock_seconds=wall,
            max_cost_micro_usd=max_cost,
            started_monotonic=now,
        )

        return cls(
            run_id=run_id,
            agent_token=agent_token,
            provider_base_url=provider_base_url,
            event_endpoint=event_endpoint,
            flag_endpoint=flag_endpoint,
            default_model=default_model,
            permitted_models=permitted,
            objective=objective,
            self_ip=self_ip,
            targets=targets,
            budget=budget,
        )


def load_task(env: Mapping[str, str] | None = None) -> dict | None:
    """Read the task descriptor from BOXR_TASK (JSON) or /destrier/task.json."""
    env = env if env is not None else os.environ
    raw = env.get("BOXR_TASK", "").strip()
    if raw:
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            pass
    path = "/destrier/task.json"
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None

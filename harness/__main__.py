"""Entrypoint: parse the contract, build the components, run the orchestrator.

Exit code is liveness only, never scoring (per the harness contract): a completed
run exits 0 regardless of how many flags it captured.
"""
from __future__ import annotations

import os
import time

from . import log
from .config import Config
from .flags import FlagSubmitter
from .gateway import Gateway
from .loop import run
from .runtime import RunContext, load_task


def _config_path() -> str | None:
    explicit = os.environ.get("HARNESS_CONFIG", "").strip()
    candidates = [explicit] if explicit else []
    candidates += ["config.yaml", os.path.join(os.path.dirname(__file__), "..", "config.yaml")]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def main() -> int:
    task = load_task(os.environ)
    try:
        ctx = RunContext.from_env(os.environ, task, now=time.monotonic())
    except ValueError as exc:
        log.error("run.misconfigured", detail=str(exc))
        return 0  # liveness only; a misconfigured run is not a crash-loop

    cfg = Config.load(_config_path(), ctx)
    for warning in cfg.warnings:
        log.warn(warning)

    headroom = float(cfg.strategy.get("retry_headroom_seconds", 20) or 0)
    call_timeout = float(cfg.strategy.get("model_call_timeout_seconds", 0) or 0)
    gateway = Gateway(
        ctx.provider_base_url, ctx.agent_token,
        budget=ctx.budget, retry_headroom_seconds=headroom,
        call_timeout=call_timeout or None,
    )
    submitter = FlagSubmitter(ctx.flag_endpoint, ctx.event_endpoint, ctx.agent_token)

    log.info(
        "run.start",
        run_id=ctx.run_id,
        objective=ctx.objective,
        targets=[t.hostname for t in ctx.targets],
        self_ip=ctx.self_ip,
        model=cfg.model_for("orchestrator", ctx),
        wall_clock_seconds=ctx.budget.wall_clock_seconds,
    )

    result = run(ctx, cfg, gateway=gateway, submitter=submitter)

    # Surface the real terminal reason as a trace event (best-effort). Without it a
    # gateway/brownout stop is indistinguishable from a healthy finish: the platform only
    # sees the process exit 0 and records stop_reason as an empty 'agent-exited'.
    submitter.emit_stop(result.reason, turns=result.turns, flags=result.flags_captured)

    log.info(
        "run.end",
        reason=result.reason,
        turns=result.turns,
        flags_captured=result.flags_captured,
        tokens=gateway.total_tokens,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

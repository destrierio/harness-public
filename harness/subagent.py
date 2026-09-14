"""Specialist sub-agents: short-lived, isolated-context tool loops with one bounded
goal. They share the run's KB, submitter, gateway and tool executor (so a foothold
session opened by one is usable by another), but keep their own message history so
the orchestrator's transcript never pollutes theirs.

Termination is by progress, not an artificial cap: a specialist ends when it calls
report_done, when it stops changing the KB for `max_stall` turns (it returns control
so the orchestrator can redirect), or when the run's cost/wall-clock ends. There is
no turn count limiting the run.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import log
from .coverage import coverage_report
from .gateway import CostExhausted, Deadline, GatewayError, ModelNotPermitted
from .kb import classify_objective, win_condition_text
from .loop import _trim_history
from .prompts import SPECIALIST_SYSTEM
from .skills import augment_system
from .tools import TurnOutputBudget, parse_tool_call, tool_specs


@dataclass
class SpecialistResult:
    role: str
    outcome: str  # success | partial | dead_end | stalled | deadline | cost_exhausted | gateway_error
    summary: str
    turns: int


def run_specialist(
    role: str,
    goal: str,
    *,
    ctx,
    cfg,
    gateway,
    submitter,
    kb,
    executor,
    now,
    max_stall: int = 4,
) -> SpecialistResult:
    system = SPECIALIST_SYSTEM.get(role)
    if system is None:
        return SpecialistResult(role=role, outcome="dead_end", summary=f"unknown specialist {role!r}", turns=0)

    override = cfg.prompts.get(f"{role}_system")
    if override:
        system = override
    system = augment_system(system, executor)
    model = cfg.model_for(role, ctx)
    temperature = _sampling(cfg, "temperature", role)
    effort = _sampling(cfg, "effort", role)
    specs = tool_specs(cfg, report_done=True)
    assignment = {"role": "user", "content": f"Your assignment: {goal}"}
    max_history_turns = max(0, int(cfg.strategy.get("max_history_turns", 0) or 0))
    win_line = (
        win_condition_text(ctx.objective)
        if bool(cfg.strategy.get("objective_aware", False))
        else None
    )
    foothold_focus = bool(cfg.strategy.get("focus_after_foothold", False))
    coverage_on = bool(cfg.strategy.get("coverage_checklist", False))
    budget_awareness = bool(cfg.strategy.get("budget_awareness", True))
    budget_below = float(cfg.strategy.get("budget_line_below_seconds", 0) or 0)
    objective_class = classify_objective(ctx.objective)

    history: list[dict] = []
    turns = 0
    stall = 0
    last_fp = kb.fingerprint()
    outcome, summary = "partial", "returned without an explicit report"

    log.info("specialist.start", role=role, goal=goal, model=model)
    while True:
        t = now()
        seconds_left = ctx.budget.seconds_left(t)
        if seconds_left <= 0:
            outcome, summary = "deadline", "wall-clock deadline reached"
            break

        if max_history_turns:
            history = _trim_history(history, max_history_turns)

        cov_text = coverage_report(kb, objective_class)[0] if coverage_on else None
        show_budget = budget_awareness and (budget_below <= 0 or seconds_left <= budget_below)
        situation = kb.situation_digest(
            ctx, seconds_left=seconds_left, tokens=gateway.total_tokens,
            win_condition=win_line, foothold_focus=foothold_focus, coverage=cov_text,
            show_budget=show_budget,
        )
        call_messages = (
            [{"role": "system", "content": system}, assignment]
            + history
            + [{"role": "user", "content": situation}]
        )
        try:
            result = gateway.chat(
                model, call_messages, tools=specs,
                temperature=temperature, effort=effort, now=now,
            )
        except CostExhausted:
            outcome, summary = "cost_exhausted", "ran out of cost budget"
            break
        except Deadline:
            outcome, summary = "deadline", "wall-clock deadline reached"
            break
        except ModelNotPermitted:
            if model != ctx.default_model:
                model = ctx.default_model
                continue
            outcome, summary = "gateway_error", "model not permitted"
            break
        except GatewayError as exc:
            outcome, summary = "gateway_error", str(exc)
            break

        turns += 1
        assistant_msg: dict = {"role": "assistant", "content": result.content}
        if result.tool_calls:
            assistant_msg["tool_calls"] = result.tool_calls
        history.append(assistant_msg)

        if result.content:
            submitter.scan(result.content)

        done = None
        output_budget = TurnOutputBudget(cfg)
        for tc in result.tool_calls:
            name, args = parse_tool_call(tc)
            if name == "report_done":
                done = (str(args.get("outcome", "success")), str(args.get("summary", "")))
                history.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                                "content": output_budget.take("acknowledged")})
                continue
            output = executor.execute(name, args)
            submitter.scan(output)
            history.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                            "content": output_budget.take(output)})

        if done is not None:
            outcome, summary = done
            break

        fp = kb.fingerprint()
        if fp == last_fp:
            stall += 1
        else:
            stall = 0
            last_fp = fp
        if stall >= max_stall:
            outcome, summary = "stalled", "no new progress; returning control to the orchestrator"
            break

    if outcome in ("dead_end", "stalled") and summary:
        kb.mark_dead(f"[{role}] {summary}")
    log.info("specialist.end", role=role, outcome=outcome, turns=turns)
    return SpecialistResult(role=role, outcome=outcome, summary=summary, turns=turns)


def _sampling(cfg, group: str, role: str):
    section = cfg.sampling.get(group, {}) if isinstance(cfg.sampling, dict) else {}
    if isinstance(section, dict) and role in section:
        value = section[role]
        if group == "temperature":
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
        return str(value) if value else None
    return None

import pytest

from harness.runtime import RunContext, Target
from helpers import BASE_ENV, TASK


def test_parses_permitted_models_as_list():
    ctx = RunContext.from_env(BASE_ENV, TASK, now=0.0)
    assert ctx.permitted_models == ("openai/gpt-x", "anthropic/claude-y")


def test_permitted_defaults_to_run_model_when_absent():
    env = {**BASE_ENV}
    del env["BOXR_MODELS"]
    ctx = RunContext.from_env(env, TASK, now=0.0)
    assert ctx.permitted_models == ("openai/gpt-x",)


def test_target_and_self_ip_from_task():
    ctx = RunContext.from_env(BASE_ENV, TASK, now=0.0)
    assert ctx.targets == (Target("box", "10.0.0.9", "entry"),)
    assert ctx.self_ip == "10.0.0.5"


def test_objective_prefers_task_then_env():
    env = {**BASE_ENV, "BOXR_OBJECTIVE": "env-obj"}
    ctx = RunContext.from_env(env, {"objective": "task-obj"}, now=0.0)
    assert ctx.objective == "task-obj"
    ctx2 = RunContext.from_env(env, None, now=0.0)
    assert ctx2.objective == "env-obj"


def test_budget_seconds_left_counts_down():
    ctx = RunContext.from_env(BASE_ENV, TASK, now=100.0)
    assert ctx.budget.seconds_left(now=100.0) == 1800
    assert ctx.budget.seconds_left(now=1000.0) == 900


def test_missing_required_var_raises_naming_it():
    env = {**BASE_ENV}
    del env["BOXR_FLAG_ENDPOINT"]
    with pytest.raises(ValueError, match="BOXR_FLAG_ENDPOINT"):
        RunContext.from_env(env, TASK, now=0.0)

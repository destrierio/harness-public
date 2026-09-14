"""models.<role> may be a single name or a priority list; first permitted wins."""
from harness.config import Config
from harness.runtime import Budget, RunContext


def _ctx(default, permitted):
    return RunContext(
        run_id="r", agent_token="t", provider_base_url="u", event_endpoint="",
        flag_endpoint="f", default_model=default, permitted_models=tuple(permitted),
        objective="o", self_ip=None, targets=(), budget=Budget(60.0, None, 0.0),
    )


def _cfg(models):
    return Config(models=models, prompts={}, strategy={}, sampling={}, tools={})


def test_single_string_permitted():
    c = _cfg({"pwn": "strong"})
    assert c.model_for("pwn", _ctx("def", ["strong", "def"])) == "strong"
    assert not c.warnings


def test_single_string_not_permitted_falls_back_with_warning():
    c = _cfg({"pwn": "strong"})
    assert c.model_for("pwn", _ctx("def", ["def"])) == "def"
    assert c.warnings


def test_auto_uses_default():
    c = _cfg({"pwn": "auto"})
    assert c.model_for("pwn", _ctx("def", ["strong", "def"])) == "def"


def test_missing_role_uses_default():
    c = _cfg({})
    assert c.model_for("web", _ctx("def", ["def"])) == "def"


def test_priority_list_prefers_first_permitted():
    c = _cfg({"pwn": ["strong", "mid", "auto"]})
    assert c.model_for("pwn", _ctx("def", ["mid", "def"])) == "mid"
    assert not c.warnings


def test_priority_list_collapses_to_default_on_single_model_event():
    c = _cfg({"pwn": ["strong", "mid", "auto"]})
    # only the default is permitted; unpermitted names skipped, 'auto' -> default
    assert c.model_for("pwn", _ctx("def", ["def"])) == "def"
    assert not c.warnings


def test_priority_list_without_auto_warns_when_none_permitted():
    c = _cfg({"pwn": ["strong", "mid"]})
    assert c.model_for("pwn", _ctx("def", ["def"])) == "def"
    assert c.warnings

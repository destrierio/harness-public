from harness.config import Config
from helpers import _ctx


def _c(models):
    return Config(models=models, prompts={}, strategy={}, sampling={}, tools={})


def test_auto_resolves_to_run_default():
    c = _c({"orchestrator": "auto"})
    assert c.model_for("orchestrator", _ctx()) == "openai/gpt-x"


def test_missing_role_resolves_to_run_default():
    c = _c({})
    assert c.model_for("pwn", _ctx()) == "openai/gpt-x"


def test_permitted_model_is_used():
    c = _c({"orchestrator": "anthropic/claude-y"})
    assert c.model_for("orchestrator", _ctx()) == "anthropic/claude-y"


def test_forbidden_model_falls_back_and_warns():
    c = _c({"orchestrator": "evil/model"})
    ctx = _ctx()
    assert c.model_for("orchestrator", ctx) == "openai/gpt-x"
    assert any("evil/model" in w for w in c.warnings)


def test_single_model_event_collapses_every_role():
    c = _c({"orchestrator": "anthropic/claude-y"})
    ctx = _ctx(models="openai/gpt-x")  # only one permitted id
    assert c.model_for("orchestrator", ctx) == "openai/gpt-x"


def test_load_never_raises_on_garbage(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("::: not yaml :::")
    c = Config.load(str(p), _ctx())  # must not raise
    assert c.model_for("orchestrator", _ctx()) == "openai/gpt-x"
    assert c.warnings  # recorded that the file could not be parsed


def test_load_missing_file_is_defaults(tmp_path):
    c = Config.load(str(tmp_path / "nope.yaml"), _ctx())
    assert c.model_for("orchestrator", _ctx()) == "openai/gpt-x"

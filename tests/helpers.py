"""Shared test helpers. Imports of harness.* are lazy so this module loads even
before a given harness submodule exists (TDD order)."""

BASE_ENV = {
    "BOXR_RUN_ID": "r1",
    "BOXR_AGENT_TOKEN": "tok",
    "BOXR_PROVIDER_BASE_URL": "http://gw/v1",
    "BOXR_EVENT_ENDPOINT": "http://gw/v1/runs/r1/events",
    "BOXR_FLAG_ENDPOINT": "http://gw/v1/runs/r1/flag",
    "BOXR_MODEL": "openai/gpt-x",
    "BOXR_MODELS": "openai/gpt-x, anthropic/claude-y",
    "BOXR_OBJECTIVE": "get root",
    "BOXR_MAX_COST_MICRO_USD": "5000000",
    "BOXR_MAX_WALL_CLOCK_SEC": "1800",
}

TASK = {
    "objective": "get root",
    "self": {"ip": "10.0.0.5"},
    "targets": [{"hostname": "box", "address": "10.0.0.9", "network": "entry"}],
}


def _ctx(models="openai/gpt-x, anthropic/claude-y", now=0.0):
    from harness.runtime import RunContext
    env = {**BASE_ENV, "BOXR_MODELS": models}
    return RunContext.from_env(env, TASK, now=now)


def _cfg(**tools):
    from harness.config import Config
    return Config(models={}, prompts={}, strategy={}, sampling={}, tools=dict(tools))


class _FakeSubmitter:
    """Stands in for FlagSubmitter: records submissions and treats every well-formed
    flag as captured, so a test asserting capture exercises the loop's scan path."""

    def __init__(self):
        self.submitted = set()
        self.captured = set()

    def submit(self, flag):
        from harness.flags import SubmitResult
        duplicate = flag in self.submitted
        self.submitted.add(flag)
        self.captured.add(flag)
        return SubmitResult(flag=flag, captured=True, duplicate=duplicate)

    def scan(self, text):
        from harness.flags import FLAG_RE
        results = []
        for flag in FLAG_RE.findall(text or ""):
            if flag not in self.submitted:
                results.append(self.submit(flag))
        return results


def _fake_submitter():
    return _FakeSubmitter()

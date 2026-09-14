"""A configurable per-call timeout. Now the reply is streamed, so this bounds the gap
BETWEEN tokens, not total generation time: a live-but-long generation is left to finish
and only a stalled stream fails fast and is retried. It is applied as the socket timeout
so each readline() blocks at most that long. Default (0/None) keeps urllib's no-deadline
behaviour so a slow provider's ~26s first token is never aborted."""
import json
import urllib.request

from harness.gateway import Gateway
from harness.runtime import Budget


def _budget(seconds=600.0):
    return Budget(wall_clock_seconds=seconds, max_cost_micro_usd=None, started_monotonic=0.0)


def _sse_ok(content="hi"):
    lines = [
        b'data: ' + json.dumps({"choices": [{"delta": {"content": content}}]}).encode() + b'\n',
        b'data: ' + json.dumps(
            {"choices": [{"delta": {}, "finish_reason": "stop"}], "usage": {"total_tokens": 1}}
        ).encode() + b'\n',
        b'data: [DONE]\n',
    ]
    return lines


class _Resp:
    """A streaming response mock: readline() serves the SSE lines, then EOF."""

    status = 200

    def __init__(self):
        self._lines = _sse_ok()

    def readline(self):
        return self._lines.pop(0) if self._lines else b""

    def read(self):
        return b"".join(self._lines)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_default_transport_passes_call_timeout_to_urlopen(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    gw = Gateway("http://gw", "t", budget=_budget(), call_timeout=40)
    r = gw.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert captured["timeout"] == 40
    assert r.content == "hi"  # the streamed reply is reassembled


def test_zero_call_timeout_means_no_client_deadline(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    gw = Gateway("http://gw", "t", budget=_budget(), call_timeout=0)
    gw.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert captured["timeout"] is None


def test_timed_out_call_is_retried_not_fatal():
    calls = {"n": 0}

    def flaky_transport(url, headers, body):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("stream stalled")
        return 200, b"".join(_sse_ok("recovered"))

    clock = [0.0]

    def now():
        clock[0] += 1.0
        return clock[0]

    gw = Gateway("http://gw", "t", budget=_budget(600.0),
                 transport=flaky_transport, sleeper=lambda s: None)
    res = gw.chat("m", [{"role": "user", "content": "x"}], now=now)
    assert res.content == "recovered"
    assert calls["n"] == 2

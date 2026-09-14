import json

import pytest

from harness.gateway import (
    Gateway, CostExhausted, Deadline, GatewayError, ModelNotPermitted, UpstreamUnavailable,
)
from harness.runtime import Budget


def budget():
    return Budget(wall_clock_seconds=1800, max_cost_micro_usd=5_000_000, started_monotonic=0.0)


def ok_body(content="hi", tokens=42, tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return json.dumps(
        {"choices": [{"message": msg, "finish_reason": "stop"}], "usage": {"total_tokens": tokens}}
    ).encode()


def gw(transport, **kw):
    return Gateway("http://gw/v1", "tok", budget=budget(), transport=transport, **kw)


def test_returns_content_and_accumulates_tokens():
    def transport(url, headers, body):
        return 200, ok_body(tokens=10)

    g = gw(transport)
    r = g.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert r.content == "hi"
    assert g.total_tokens == 10


def test_402_raises_cost_exhausted():
    def transport(url, headers, body):
        return 402, b'{"error":"budget"}'

    with pytest.raises(CostExhausted):
        gw(transport).chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)


def test_400_model_not_permitted_raises():
    def transport(url, headers, body):
        return 400, b'{"error":"model not permitted"}'

    with pytest.raises(ModelNotPermitted):
        gw(transport).chat("bad", [{"role": "user", "content": "x"}], now=lambda: 0.0)


def test_extracts_tool_calls():
    tc = [{"id": "c1", "type": "function", "function": {"name": "shell", "arguments": '{"command":"ls"}'}}]

    def transport(url, headers, body):
        return 200, ok_body(content=None, tool_calls=tc)

    r = gw(transport).chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert r.tool_calls[0]["function"]["name"] == "shell"


def test_429_retries_then_succeeds():
    seq = [(429, b'{"error":"rate"}'), (200, ok_body())]

    def transport(url, headers, body):
        return seq.pop(0)

    slept = []
    r = gw(transport, sleeper=slept.append).chat(
        "m", [{"role": "user", "content": "x"}], now=lambda: 0.0
    )
    assert r.content == "hi"
    assert slept  # backed off once


def test_400_naming_a_param_drops_it_and_retries():
    bodies = []
    seq = [(400, b'{"error":"temperature is not supported by this model"}'), (200, ok_body())]

    def transport(url, headers, body):
        bodies.append(json.loads(body))
        return seq.pop(0)

    r = gw(transport).chat(
        "m", [{"role": "user", "content": "x"}], temperature=0.7, now=lambda: 0.0
    )
    assert r.content == "hi"
    assert "temperature" in bodies[0]  # first attempt included it
    assert "temperature" not in bodies[1]  # retry dropped it


# --- transient-upstream retry (P4): one hiccup must not end a deadline-bound run ---

def test_5xx_retries_then_succeeds():
    seq = [(503, b'{"error":"upstream"}'), (200, ok_body())]

    def transport(url, headers, body):
        return seq.pop(0)

    slept = []
    r = gw(transport, sleeper=slept.append).chat(
        "m", [{"role": "user", "content": "x"}], now=lambda: 0.0
    )
    assert r.content == "hi"
    assert slept  # backed off before retrying


def test_empty_200_upstream_error_is_retried():
    # a 200 with no choices is an upstream_error masquerading as success
    empty = json.dumps({"error": {"message": "upstream_error"}}).encode()
    seq = [(200, empty), (200, ok_body())]

    def transport(url, headers, body):
        return seq.pop(0)

    slept = []
    r = gw(transport, sleeper=slept.append).chat(
        "m", [{"role": "user", "content": "x"}], now=lambda: 0.0
    )
    assert r.content == "hi"
    assert slept


def test_transport_exception_is_retried():
    calls = {"n": 0}

    def transport(url, headers, body):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("connection reset")
        return 200, ok_body()

    r = gw(transport, sleeper=lambda _s: None).chat(
        "m", [{"role": "user", "content": "x"}], now=lambda: 0.0
    )
    assert r.content == "hi"
    assert calls["n"] == 2


def test_normal_empty_stop_is_not_retried():
    # a genuine empty completion (choices present, finish_reason set) is returned as-is
    body = json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}],
         "usage": {"total_tokens": 3}}
    ).encode()
    calls = {"n": 0}

    def transport(url, headers, body_):
        calls["n"] += 1
        return 200, body

    r = gw(transport).chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert r.content == ""
    assert calls["n"] == 1  # not retried


def test_404_still_raises_gateway_error():
    def transport(url, headers, body):
        return 404, b'{"error":"not found"}'

    with pytest.raises(GatewayError):
        gw(transport).chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)


def test_persistent_5xx_at_cap_with_time_left_is_upstream_unavailable():
    # Cap hit while budget AND wall-clock still have room => a provider brownout the
    # LOOP should cool down and retry, NOT a Deadline that ends the run. (Was: Deadline.)
    def transport(url, headers, body):
        return 503, b'{"error":"down"}'

    g = Gateway("http://gw/v1", "tok", budget=budget(), transport=transport,
                sleeper=lambda _s: None, max_retries=2)
    with pytest.raises(UpstreamUnavailable):
        g.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert issubclass(UpstreamUnavailable, GatewayError)  # still a gateway error subtype


def test_empty_200_exhausted_with_time_left_is_upstream_unavailable():
    # An empty upstream_error 200 that never recovers used to be RETURNED as an empty
    # result (a wasted turn); now, once the retry cap is hit with time to spare, it is
    # raised as UpstreamUnavailable so the loop can wait the brownout out.
    empty = json.dumps({"error": {"message": "upstream_error"}}).encode()

    def transport(url, headers, body):
        return 200, empty

    g = Gateway("http://gw/v1", "tok", budget=budget(), transport=transport,
                sleeper=lambda _s: None, max_retries=2)
    with pytest.raises(UpstreamUnavailable):
        g.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)


def test_transport_exhausted_with_time_left_is_upstream_unavailable():
    def transport(url, headers, body):
        raise TimeoutError("hung socket")

    g = Gateway("http://gw/v1", "tok", budget=budget(), transport=transport,
                sleeper=lambda _s: None, max_retries=2)
    with pytest.raises(UpstreamUnavailable):
        g.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)


def test_cap_hit_near_the_deadline_is_deadline_not_upstream_unavailable():
    # When the wall-clock HEADROOM is what stops the retries (not spare-time cap), it is a
    # genuine Deadline: act on what we have, don't cool down into the tail of the run.
    def transport(url, headers, body):
        return 503, b'{"error":"down"}'

    # headroom >= whole budget => seconds_left is never above headroom => Deadline path.
    g = Gateway("http://gw/v1", "tok", budget=budget(), transport=transport,
                sleeper=lambda _s: None, max_retries=2, retry_headroom_seconds=100_000)
    with pytest.raises(Deadline):
        g.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)


def test_retries_respect_advancing_deadline_and_never_oversleep():
    # The frozen-clock bug: with now pinned, the deadline check never advanced and
    # retries were bounded only by the cap. With a LIVE clock (sleeping advances it),
    # a persistent 5xx must give up on the wall-clock deadline, and no single capped
    # sleep may take total sleep past the budget.
    def transport(url, headers, body):
        return 503, b'{"error":"down"}'

    clock = {"t": 0.0}
    slept = []

    def now():
        return clock["t"]

    def sleeper(s):
        slept.append(s)
        clock["t"] += s  # a real sleep advances the live clock

    g = Gateway("http://gw/v1", "tok", budget=budget(), transport=transport,
                sleeper=sleeper, max_retries=100_000)  # cap high, so the DEADLINE must stop it
    with pytest.raises(Deadline):
        g.chat("m", [{"role": "user", "content": "x"}], now=now)
    assert sum(slept) <= 1800.0 + 1e-6          # never overslept the wall-clock budget
    assert clock["t"] >= 1800.0                  # stopped because time ran out, not the cap
    assert all(s <= 15.0 for s in slept)         # each sleep still capped at the backoff ceiling


def test_serialization_error_is_not_retried():
    # A non-serializable body must surface as a real error, not be retried as a
    # phantom transport failure (json.dumps is outside the retry try).
    calls = {"n": 0}

    def transport(url, headers, body):
        calls["n"] += 1
        return 200, ok_body()

    unserializable = [{"role": "user", "content": {1, 2, 3}}]  # a set is not JSON
    with pytest.raises(TypeError):
        gw(transport).chat("m", unserializable, now=lambda: 0.0)
    assert calls["n"] == 0  # never even reached the transport


def test_time_burned_inside_a_slow_failed_call_counts_and_headroom_stops_retries():
    # The 120s upstream_error hang: the call itself burns wall-clock. The live-clock
    # guard must count that (not just backoff sleeps), and the headroom must stop
    # starting new retries before the tail of the run is gone.
    clock = {"t": 0.0}
    calls = {"n": 0}

    def now():
        return clock["t"]

    def transport(url, headers, body):
        calls["n"] += 1
        clock["t"] += 200.0            # each failed call itself burns 200s of wall-clock
        return 503, b'{"error":"slow-fail"}'

    g = Gateway("http://gw/v1", "tok", budget=budget(), transport=transport,
                sleeper=lambda _s: None, max_retries=100, retry_headroom_seconds=100)
    with pytest.raises(Deadline):
        g.chat("m", [{"role": "user", "content": "x"}], now=now)
    # budget 1800, 200s/failed-call, headroom 100 => retry only while remaining > 100,
    # i.e. while clock < 1700 => ~9 calls, then it stops with ~100s still unspent.
    assert calls["n"] <= 10                       # bounded by elapsed-in-call, not just sleeps/cap
    assert (1800.0 - clock["t"]) <= 100.0         # stopped at the headroom threshold


# --- streaming (SSE) reassembly: the reply is streamed so the timeout bounds the gap
# between tokens, not total generation time; the turn is rebuilt from the deltas. ---

def sse(*chunks):
    lines = [b"data: " + json.dumps(c).encode() + b"\n" for c in chunks]
    lines.append(b"data: [DONE]\n")
    return b"".join(lines)


def test_streaming_content_reassembles_and_counts_tokens():
    body = sse(
        {"choices": [{"delta": {"role": "assistant", "content": "he"}}]},
        {"choices": [{"delta": {"content": "llo"}}]},
        {"choices": [{"delta": {}, "finish_reason": "stop"}], "usage": {"total_tokens": 7}},
    )
    g = gw(lambda u, h, b: (200, body))
    r = g.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert r.content == "hello"
    assert r.finish_reason == "stop"
    assert r.total_tokens == 7
    assert g.total_tokens == 7


def test_streaming_tool_calls_reassemble_across_chunks():
    # id + name arrive first; arguments arrive split across later chunks, keyed by index.
    body = sse(
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "c1", "type": "function", "function": {"name": "shell", "arguments": ""}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"comm'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": 'and":"ls"}'}}]}}]},
        {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
    )
    r = gw(lambda u, h, b: (200, body)).chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert len(r.tool_calls) == 1
    tc = r.tool_calls[0]
    assert tc["id"] == "c1"
    assert tc["function"]["name"] == "shell"
    assert json.loads(tc["function"]["arguments"]) == {"command": "ls"}
    assert r.finish_reason == "tool_calls"


def test_streaming_keepalive_comments_and_blank_lines_are_ignored():
    body = (
        b": OPENROUTER PROCESSING\n\n"
        + sse({"choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}],
               "usage": {"total_tokens": 2}})
    )
    r = gw(lambda u, h, b: (200, body)).chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert r.content == "ok"


def test_streaming_error_only_chunk_is_empty_and_retried():
    # a stream that carries only an error chunk is an upstream_error: retry, don't
    # return it as a wasted turn.
    err = b'data: {"error":{"message":"upstream"}}\n\ndata: [DONE]\n'
    good = sse({"choices": [{"delta": {"content": "recovered"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1}})
    seq = [(200, err), (200, good)]
    r = gw(lambda u, h, b: seq.pop(0), sleeper=lambda _s: None).chat(
        "m", [{"role": "user", "content": "x"}], now=lambda: 0.0
    )
    assert r.content == "recovered"


def test_default_stream_transport_retries_on_readline_stall(monkeypatch):
    # The real default transport: a stalled stream makes readline raise TimeoutError,
    # which is retried on a fresh call that streams to completion.
    import urllib.request as u
    good = sse({"choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1}})

    class _Stall:
        status = 200
        def readline(self):
            raise TimeoutError("stream stalled")
        def read(self):
            return b""
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    class _Good:
        status = 200
        def __init__(self):
            self._served = False
        def readline(self):
            if self._served:
                return b""
            self._served = True
            return good
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    resps = [_Stall(), _Good()]
    monkeypatch.setattr(u, "urlopen", lambda req, timeout=None: resps.pop(0))
    g = Gateway("http://gw/v1", "tok", budget=budget(), call_timeout=30, sleeper=lambda _s: None)
    r = g.chat("m", [{"role": "user", "content": "x"}], now=lambda: 0.0)
    assert r.content == "ok"
    assert not resps  # both responses were consumed (stall then success)

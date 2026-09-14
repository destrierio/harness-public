"""OpenAI-spec /chat/completions client for the metered gateway.

Encodes the parts of the contract that are load-bearing and were historically
mis-stated in docs: 402 = cost exhausted (end the run), 429 = rate limit (back off,
bounded by the wall-clock deadline, never a retry count), 400 naming a sampling
param = drop it once and retry, 400 naming the model = the model is not permitted.
The network path is injectable so tests need no sockets.
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from .runtime import Budget

# Network-level failures worth retrying as transient: socket timeout / reset
# (OSError, and urllib.error.URLError which subclasses it), and a mid-stream
# protocol error (IncompleteRead is an HTTPException). Deliberately narrow — a
# programming error (e.g. a non-serializable message) must surface, not be retried.
_TRANSIENT_TRANSPORT_ERRORS = (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException)


class GatewayError(Exception):
    """A non-retryable gateway response that is not one of the modelled cases."""


class CostExhausted(GatewayError):
    """Gateway returned 402: the run's cost budget is spent."""


class ModelNotPermitted(GatewayError):
    """Gateway returned 400 rejecting the requested model."""


class Deadline(GatewayError):
    """The wall-clock deadline (or its retry-headroom margin) is what stopped the retries:
    act on what we already have, do not keep waiting into the tail of the run."""


class UpstreamUnavailable(GatewayError):
    """Transient upstream failures (socket timeouts / 5xx / an empty-200 upstream_error)
    exhausted the retry cap, but the run's cost budget AND wall-clock still have room. A
    provider brownout the LOOP should cool down and retry — NOT a reason to end the run.
    Distinct from Deadline (which means time, not the provider, is the binding limit)."""


@dataclass
class ChatResult:
    content: str | None
    tool_calls: list[dict]
    finish_reason: str
    total_tokens: int
    prompt_tokens: int = 0  # real size of the prompt we sent (usage.prompt_tokens); 0 if absent


# param name in the request body -> substring the gateway uses to reject it
_DROPPABLE_PARAMS = ("temperature", "reasoning_effort", "max_tokens")


def _is_empty_result(raw: bytes, result: "ChatResult") -> bool:
    """True when a 200 carried no usable turn — no choices, or an error body, or a
    choice with neither content nor tool calls. A genuine empty *stop* (choices
    present, finish_reason set) is NOT flagged, so we never retry a real answer."""
    if result.tool_calls or (result.content and result.content.strip()):
        return False
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return True
    if not isinstance(data, dict):
        return True
    if data.get("error"):
        return True
    if not data.get("choices"):
        return True
    return not (result.finish_reason or "").strip()

Transport = Callable[[str, Mapping[str, str], bytes], tuple[int, bytes]]


def _looks_like_sse(raw: bytes) -> bool:
    """An OpenAI streaming reply is SSE: its first non-blank bytes are an event field
    (`data:`/`event:`) or a `:` keepalive comment. A buffered JSON completion (what the
    test transports return, and the non-stream shape) starts with `{`."""
    head = raw.lstrip()
    return head.startswith(b"data:") or head.startswith(b"event:") or head.startswith(b":")


def _urllib_transport(
    url: str, headers: Mapping[str, str], body: bytes, timeout: float | None = None
) -> tuple[int, bytes]:
    """Stream the SSE reply and accumulate it, so `timeout` bounds the gap BETWEEN
    tokens rather than the whole generation. A live generation keeps emitting tokens
    (and OpenRouter interleaves `: ...` keepalive comments), so it is never aborted
    however long it runs — the run's wall-clock deadline, checked in the loop between
    calls, is the real ceiling. Only a stalled stream (no first token, or a mid-stream
    hang) trips the per-read socket timeout, raises TimeoutError, and is retried as a
    transient upstream failure. A non-200 carries a normal buffered error body."""
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        # timeout=None keeps urllib's default (no client-side deadline). A positive
        # value is applied to the socket, so each readline() below blocks at most that
        # long: a stream that goes quiet is killed fast and retried, a stream that keeps
        # producing tokens is left to finish.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted internal gateway)
            status = getattr(resp, "status", 200)
            if status != 200:
                return status, resp.read()
            parts: list[bytes] = []
            while True:
                line = resp.readline()
                if not line:
                    break
                parts.append(line)
            return status, b"".join(parts)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class Gateway:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        budget: Budget,
        transport: Transport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        max_retries: int = 8,
        retry_headroom_seconds: float = 0.0,
        call_timeout: float | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.budget = budget
        # call_timeout now bounds INACTIVITY, not total time: the reply is streamed, so
        # this caps the gap between tokens (and the wait for the first token). A live
        # generation keeps streaming and is never aborted however long it runs — this is
        # what stops a large-context call late in a stage being killed mid-answer. Only a
        # stalled stream (dead socket / no first token) fails fast and is retried. None =
        # urllib default (no client-side deadline). Bound into the default transport only;
        # an injected transport keeps its (url, headers, body) shape.
        self._call_timeout = call_timeout if (call_timeout and call_timeout > 0) else None
        if transport is not None:
            self._transport = transport
        else:
            self._transport = lambda u, h, b: _urllib_transport(u, h, b, timeout=self._call_timeout)
        self._sleeper = sleeper
        self._max_retries = max(0, int(max_retries))
        self._headroom = max(0.0, float(retry_headroom_seconds))
        self.total_tokens = 0

    def chat(
        self,
        model: str,
        messages: Sequence[dict],
        *,
        tools: Sequence[dict] | None = None,
        temperature: float | None = None,
        effort: str | None = None,
        max_tokens: int | None = None,
        now: Callable[[], float],
    ) -> ChatResult:
        # stream=true so the per-call timeout measures the gap between tokens, not total
        # generation time: a long-but-progressing answer (common late in a stage, when
        # the context is large) finishes instead of being killed by a total-time cap. The
        # gateway routes stream=true to its SSE path and injects usage reporting.
        body: dict = {"model": model, "messages": list(messages), "stream": True}
        if tools:
            body["tools"] = list(tools)
        if temperature is not None:
            body["temperature"] = temperature
        if effort is not None:
            body["reasoning_effort"] = effort
        if max_tokens is not None:
            body["max_tokens"] = max_tokens

        dropped: set[str] = set()
        backoff = 1.0
        transient = 0
        while True:
            # Serialize OUTSIDE the try so a non-serializable body raises a real error
            # instead of being retried as a phantom "transport failure".
            payload = json.dumps(body).encode()
            # A transport-level failure (socket timeout, dropped connection) is a
            # transient upstream problem, not a reason to end the run — retry it on
            # bounded backoff, capped by the wall-clock deadline. NB: no client-side
            # request timeout is imposed (urlopen default), on purpose: a healthy first
            # token can take ~26s with some providers, so we never abort a slow-but-live
            # call and never retry one that was going to succeed. The model call is
            # re-requested here BEFORE any tool runs (tools execute in the loop after
            # chat() returns), so a retry never replays a tool — retries are idempotent.
            try:
                status, raw = self._transport(self._url, self._headers, payload)
            except _TRANSIENT_TRANSPORT_ERRORS as exc:
                if not self._retry_transient(now, transient):
                    raise self._give_up(now, transient, f"transport failed: {exc}") from exc
                transient += 1
                backoff = self._backoff_sleep(now, backoff)
                continue
            if status == 200:
                result = self._parse_ok(raw)
                # A 200 that carries no usable turn is an upstream_error masquerading as
                # success (the callSeq-5 hang that killed a live run). Treat it as
                # transient so one hiccup does not end the run a turn before the flag.
                if _is_empty_result(raw, result):
                    if not self._retry_transient(now, transient):
                        # Exhausted on an empty body: raise (classified) rather than return
                        # the empty result as a wasted turn, so the loop can wait it out.
                        raise self._give_up(now, transient, "empty upstream_error (200)")
                    transient += 1
                    backoff = self._backoff_sleep(now, backoff)
                    continue
                return result
            if status == 402:
                raise CostExhausted(raw.decode(errors="replace"))
            if status == 429 or status == 408 or status >= 500:
                if not self._retry_transient(now, transient):
                    raise self._give_up(now, transient, f"gateway {status}")
                transient += 1
                backoff = self._backoff_sleep(now, backoff)
                continue
            if status == 400:
                text = raw.decode(errors="replace").lower()
                retried = False
                for param in _DROPPABLE_PARAMS:
                    if param in text and param in body and param not in dropped:
                        body.pop(param, None)
                        dropped.add(param)
                        retried = True
                        break
                if retried:
                    continue
                if "model" in text:
                    raise ModelNotPermitted(text)
                raise GatewayError(f"400 from gateway: {text}")
            raise GatewayError(f"{status} from gateway: {raw.decode(errors='replace')}")

    def _retry_transient(self, now: Callable[[], float], attempts: int) -> bool:
        """A transient upstream failure is worth another attempt only while the retry
        cap allows AND enough wall-clock remains that a retry won't spend the tail of
        the run. `now` MUST be a live (advancing) clock — the loop passes the real
        monotonic clock, not the frozen per-turn timestamp — so this counts BOTH the
        backoff sleeps AND the time burned inside a slow failed call (a single failed
        model call has hung ~120s). The headroom leaves time to act on what we already
        found instead of retrying into the deadline. 0 headroom = retry while any time
        remains."""
        return attempts < self._max_retries and self.budget.seconds_left(now()) > self._headroom

    def _give_up(self, now: Callable[[], float], attempts: int, detail: str) -> GatewayError:
        """Classify WHY the retries stopped, so the loop can tell a brownout to wait out
        from a genuine deadline. If the wall-clock headroom is the binding limit it is a
        Deadline (act on what we have); if the retry cap was hit while budget and time
        remain it is an UpstreamUnavailable (a provider brownout the loop can cool down and
        retry). `now` is the live clock, so this sees time burned inside slow failed calls."""
        if self.budget.seconds_left(now()) <= self._headroom:
            return Deadline(f"gateway past the wall-clock deadline / retry cap ({detail})")
        return UpstreamUnavailable(f"upstream unavailable after {attempts} retries ({detail})")

    def _backoff_sleep(self, now: Callable[[], float], backoff: float) -> float:
        """Sleep the current backoff, but never longer than the budget that remains,
        so a burst of retries can never oversleep the wall-clock deadline. Returns the
        next (doubled, capped) backoff."""
        remaining = self.budget.seconds_left(now())
        self._sleeper(min(backoff, max(0.0, remaining)))
        return min(backoff * 2, 15.0)

    def _parse_ok(self, raw: bytes) -> ChatResult:
        result = self._parse_stream(raw) if _looks_like_sse(raw) else self._parse_json(raw)
        self.total_tokens += result.total_tokens
        return result

    @staticmethod
    def _parse_json(raw: bytes) -> ChatResult:
        data = json.loads(raw)
        usage = data.get("usage") or {}
        tokens = int(usage.get("total_tokens") or 0)
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        return ChatResult(
            content=msg.get("content"),
            tool_calls=list(msg.get("tool_calls") or []),
            finish_reason=choice.get("finish_reason") or "",
            total_tokens=tokens,
            prompt_tokens=prompt_tokens,
        )

    @staticmethod
    def _parse_stream(raw: bytes) -> ChatResult:
        """Reassemble an OpenAI-style SSE stream into one turn. Content deltas concatenate
        in arrival order; tool-call deltas are keyed by their `index` and their id / name /
        argument fragments are stitched per index (arguments arrive split across chunks).
        Usage arrives in a final chunk (the gateway asks the upstream to include it). Lines
        that are not `data:` events (blank lines, `: ...` keepalive comments) are ignored."""
        content_parts: list[str] = []
        by_index: dict[int, dict] = {}
        order: list[int] = []
        finish_reason = ""
        tokens = 0
        prompt_tokens = 0
        for rawline in raw.split(b"\n"):
            line = rawline.strip()
            if not line.startswith(b"data:"):
                continue
            payload = line[len(b"data:"):].strip()
            if not payload or payload == b"[DONE]":
                continue
            try:
                chunk = json.loads(payload)
            except (ValueError, TypeError):
                continue
            if not isinstance(chunk, dict):
                continue
            usage = chunk.get("usage")
            if usage:
                tokens = int(usage.get("total_tokens") or 0) or tokens
                prompt_tokens = int(usage.get("prompt_tokens") or 0) or prompt_tokens
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                piece = delta.get("content")
                if piece:
                    content_parts.append(piece)
                for tc in delta.get("tool_calls") or []:
                    idx = tc.get("index")
                    if idx is None:
                        idx = len(order)
                    slot = by_index.get(idx)
                    if slot is None:
                        slot = {"id": None, "type": "function", "name": "", "args": []}
                        by_index[idx] = slot
                        order.append(idx)
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    if tc.get("type"):
                        slot["type"] = tc["type"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] += fn["name"]
                    if fn.get("arguments"):
                        slot["args"].append(fn["arguments"])
                if choice.get("finish_reason"):
                    finish_reason = choice["finish_reason"]
        tool_calls = [
            {
                "id": by_index[i]["id"],
                "type": by_index[i]["type"],
                "function": {"name": by_index[i]["name"], "arguments": "".join(by_index[i]["args"])},
            }
            for i in order
        ]
        return ChatResult(
            content="".join(content_parts) or None,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            total_tokens=tokens,
            prompt_tokens=prompt_tokens,
        )

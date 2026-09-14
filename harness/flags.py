"""Flag detection and submission.

Submitting is what scores, not finding, so every tool output and model message is
scanned in addition to the explicit submit_flag tool. Submission is deduplicated
(a wrong flag is a 200 with captured:false, not an error), and a capture emits the
one self-report the contract allows: objective.claimed.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass

FLAG_RE = re.compile(r"destrier\{[a-z0-9_]*[0-9][a-z0-9_]*\}")

Transport = Callable[[str, Mapping[str, str], bytes], tuple[int, bytes]]


def _urllib_transport(url: str, headers: Mapping[str, str], body: bytes) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 (trusted internal endpoint)
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@dataclass
class SubmitResult:
    flag: str
    captured: bool
    duplicate: bool


class FlagSubmitter:
    def __init__(
        self,
        flag_endpoint: str,
        event_endpoint: str,
        token: str,
        *,
        transport: Transport | None = None,
    ) -> None:
        self._flag_endpoint = flag_endpoint
        self._event_endpoint = event_endpoint
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._transport = transport or _urllib_transport
        self.submitted: set[str] = set()
        self.captured: set[str] = set()

    def submit(self, flag: str) -> SubmitResult:
        if flag in self.submitted:
            return SubmitResult(flag=flag, captured=flag in self.captured, duplicate=True)
        self.submitted.add(flag)

        status, raw = self._transport(
            self._flag_endpoint, self._headers, json.dumps({"flag": flag}).encode()
        )
        captured = False
        if status == 200:
            try:
                captured = bool(json.loads(raw).get("captured"))
            except (ValueError, TypeError):
                captured = False
        if captured:
            self.captured.add(flag)
            self._emit_claim(flag)
        return SubmitResult(flag=flag, captured=captured, duplicate=False)

    def scan(self, text: str) -> list[SubmitResult]:
        results: list[SubmitResult] = []
        for flag in FLAG_RE.findall(text or ""):
            if flag not in self.submitted:
                results.append(self.submit(flag))
        return results

    def _emit(self, event_type: str, **fields) -> None:
        """Best-effort telemetry: POST an event to the run's event sink. Never raises —
        a down sink must never affect the run."""
        if not self._event_endpoint:
            return
        payload = json.dumps({"type": event_type, **fields}).encode()
        try:
            self._transport(self._event_endpoint, self._headers, payload)
        except Exception:  # noqa: BLE001 - event telemetry is best-effort
            pass

    def _emit_claim(self, flag: str) -> None:
        self._emit("objective.claimed", flag=flag)

    def emit_stop(self, reason: str, *, turns: int = 0, flags: int = 0, detail: str = "") -> None:
        """Record WHY the run ended as a trace event, so a gateway/brownout stop is visible
        instead of looking like a healthy 'agent-exited' with an empty stop_reason. The
        event lands in the run trace today; mapping it onto the platform's stop_reason
        column is a small platform-side follow-up."""
        self._emit("agent.stopped", reason=reason, turns=turns, flags=flags,
                   detail=(detail or "")[:500])

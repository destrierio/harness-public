"""A standard-library mock of the Destrier gateway: an OpenAI /chat/completions
endpoint that returns scripted assistant turns, a flag endpoint that captures only
the real flag, and an events sink. When the script is drained it returns 402, so
the real orchestrator loop ends on cost exhaustion exactly as it would in a run.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_gateway_server(port: int, script: list[dict], real_flag: str) -> ThreadingHTTPServer:
    state = {"script": list(script), "flag_posts": [], "real_flag": real_flag}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the test output quiet
            pass

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802 (http.server API)
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length else b""

            if self.path.endswith("/chat/completions"):
                if state["script"]:
                    msg = dict(state["script"].pop(0))
                    finish = "tool_calls" if msg.get("tool_calls") else "stop"
                    self._send(200, {
                        "choices": [{"message": msg, "finish_reason": finish}],
                        "usage": {"total_tokens": 1},
                    })
                else:
                    self._send(402, {"error": "budget exhausted"})
            elif self.path.endswith("/flag"):
                try:
                    flag = json.loads(raw).get("flag")
                except (ValueError, TypeError):
                    flag = None
                state["flag_posts"].append(flag)
                captured = flag == state["real_flag"]
                self._send(200, {"captured": captured, "objectiveId": "o1" if captured else None})
            elif self.path.endswith("/events"):
                self._send(200, {})
            else:
                self._send(404, {"error": "not found"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.mock_state = state  # type: ignore[attr-defined]
    return server

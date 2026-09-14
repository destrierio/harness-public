import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from harness.http_client import HttpClient


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/hello":
            body = b"hello world"
            self.send_response(200)
        elif self.path == "/setcookie":
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            body = b"set"
        elif self.path == "/whoami":
            cookie = self.headers.get("Cookie", "")
            body = f"cookie: {cookie}".encode()
            self.send_response(200)
        else:
            self.send_response(404)
            body = b"nope"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_get_returns_status_and_body(server):
    r = HttpClient().request("GET", f"{server}/hello")
    assert r["status"] == 200
    assert r["body"] == "hello world"


def test_cookies_persist_across_requests(server):
    c = HttpClient()
    c.request("GET", f"{server}/setcookie")
    r = c.request("GET", f"{server}/whoami")
    assert "sid=abc123" in r["body"]


def test_http_error_returns_status_not_raise(server):
    r = HttpClient().request("GET", f"{server}/missing")
    assert r["status"] == 404


def test_get_bytes(server):
    status, data = HttpClient().get_bytes(f"{server}/hello")
    assert status == 200
    assert data == b"hello world"


def test_request_routes_through_injected_proxy_opener():
    from harness.http_client import HttpClient

    class _R:
        def __init__(self): self.opened = []
        def open(self, req, timeout=None):
            self.opened.append(req.full_url)
            class Resp:
                status = 200
                headers = {}
                def read(self): return b"via-proxy"
                def __enter__(self): return self
                def __exit__(self, *a): return False
            return Resp()

    rec = _R()
    c = HttpClient(proxy_opener=rec)
    r = c.request("GET", "http://inner/x", proxy="127.0.0.1:1080")
    assert r["status"] == 200 and "via-proxy" in r["body"]
    assert rec.opened == ["http://inner/x"]


def test_proxy_without_backend_degrades_gracefully():
    from harness.http_client import HttpClient
    r = HttpClient().request("GET", "http://inner/x", proxy="127.0.0.1:9")
    assert r["status"] == 0 and "error" in r["body"].lower()

"""http_request auto-negotiates HTTP Basic/Digest auth when creds are supplied."""
import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import urllib.request

from harness.http_client import HttpClient


def _basic_auth_server(user, pw):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            hdr = self.headers.get("Authorization", "")
            ok = False
            if hdr.startswith("Basic "):
                try:
                    ok = base64.b64decode(hdr.split(" ", 1)[1]).decode() == f"{user}:{pw}"
                except Exception:  # noqa: BLE001
                    ok = False
            if not ok:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="test"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"secret-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_basic_auth_negotiated_with_creds():
    srv = _basic_auth_server("admin", "pw123")
    port = srv.server_address[1]
    try:
        r = HttpClient().request("GET", f"http://127.0.0.1:{port}/x",
                                 auth={"username": "admin", "password": "pw123"})
    finally:
        srv.shutdown()
    assert r["status"] == 200 and "secret-ok" in r["body"]


def test_without_creds_gets_401():
    srv = _basic_auth_server("admin", "pw123")
    port = srv.server_address[1]
    try:
        r = HttpClient().request("GET", f"http://127.0.0.1:{port}/x")
    finally:
        srv.shutdown()
    assert r["status"] == 401


def test_digest_handler_is_wired():
    # a Digest challenge (an IP camera's login) must be answerable, not just Basic
    c = HttpClient()
    assert any(isinstance(h, urllib.request.HTTPDigestAuthHandler) for h in c._opener.handlers)

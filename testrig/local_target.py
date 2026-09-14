"""A trivial vulnerable target: the flag is served ONLY through the traversal path
(?file=../flag), never from the landing page. A harness that does not actually run
the exploit gets a boring page and captures nothing — so the e2e proves the loop,
not a rubber stamp.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def make_target_server(port: int, flag: str) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802 (http.server API)
            file_param = parse_qs(urlparse(self.path).query).get("file", [""])[0]
            if "flag" in file_param:  # traversal reaches the flag file
                body = flag.encode()
            else:
                body = b"<html><body>Welcome to the widget portal</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)

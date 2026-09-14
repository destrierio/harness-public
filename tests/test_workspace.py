import hashlib
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from harness.workspace import Workspace

ELF = b"\x7fELF" + b"\x02\x01\x01\x00" + b"A" * 200


@pytest.fixture
def binary_server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", str(len(ELF)))
            self.end_headers()
            self.wfile.write(ELF)

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


class _Client:
    def get_bytes(self, url, timeout=30.0):
        from harness.http_client import HttpClient
        return HttpClient().get_bytes(url, timeout)


def test_fetch_url_registers_artifact(binary_server, tmp_path):
    ws = Workspace(root=str(tmp_path))
    art = ws.fetch_url(f"{binary_server}/vuln", _Client(), name="vuln")
    assert art.sha256 == hashlib.sha256(ELF).hexdigest()
    with open(art.path, "rb") as fh:
        assert fh.read() == ELF


def test_register_path_hashes_existing_file(tmp_path):
    ws = Workspace(root=str(tmp_path))
    p = ws.write_bytes("note.txt", b"contents")
    art = ws.register_path(p, source="shell")
    assert art.name == "note.txt"
    assert art.sha256 == hashlib.sha256(b"contents").hexdigest()


def test_path_is_confined_to_workspace(tmp_path):
    ws = Workspace(root=str(tmp_path))
    # a traversal-y name must not escape the workspace root
    p = ws.path("../../etc/passwd")
    assert p.startswith(str(tmp_path))

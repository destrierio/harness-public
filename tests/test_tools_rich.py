import subprocess

from harness.kb import KB
from harness.tools import ToolExecutor, tool_specs
from harness.workspace import Workspace
from helpers import _cfg, _ctx, _fake_submitter


def _ex(**kw):
    return ToolExecutor(_ctx(), KB(), _fake_submitter(), _cfg(), **kw)


class _FakeHttp:
    def request(self, method, url, headers=None, body=None, timeout=20.0, auth=None):
        return {"status": 200, "headers": {"Content-Type": "text/html"}, "body": f"{method} {url} body"}

    def get_bytes(self, url, timeout=30.0):
        return 200, b"\x7fELFbinarybytes"


def test_session_tool_open_and_send():
    ex = _ex()
    try:
        assert "opened" in ex.execute("session", {"action": "open", "name": "s"})
        out = ex.execute("session", {"action": "send", "name": "s", "data": "echo tool_hi", "timeout": 3})
        assert "tool_hi" in out
    finally:
        ex.close()


def test_python_exec_tool():
    ex = _ex()
    try:
        assert "42" in ex.execute("python_exec", {"code": "print(6 * 7)"})
    finally:
        ex.close()


def test_http_request_tool_formats_response():
    ex = _ex(http=_FakeHttp())
    out = ex.execute("http_request", {"method": "GET", "url": "http://t/x"})
    assert "status: 200" in out
    assert "GET http://t/x body" in out


def test_fetch_artifact_tool_registers_in_kb(tmp_path):
    kb = KB()
    ex = ToolExecutor(_ctx(), kb, _fake_submitter(), _cfg(), http=_FakeHttp(), workspace=Workspace(root=str(tmp_path)))
    out = ex.execute("fetch_artifact", {"url": "http://t/vuln", "name": "vuln"})
    assert "vuln" in out
    assert kb.artifacts and kb.artifacts[0].name == "vuln"


def test_browser_tool_uses_injected_runner():
    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, stdout="<html><body>rendered DOM</body></html>", stderr="")

    ex = _ex(browser_runner=runner)
    out = ex.execute("browser", {"url": "http://t/app"})
    assert "rendered DOM" in out


def test_reverse_shell_listener_tool():
    ex = _ex()
    try:
        start = ex.execute("reverse_shell_listener", {"action": "start", "port": 0})
        assert "listening" in start.lower()
        status = ex.execute("reverse_shell_listener", {"action": "status"})
        assert "listening" in status.lower() or "caught" in status.lower()
    finally:
        ex.close()


def test_disabled_tool_is_absent_from_specs():
    names = {s["function"]["name"] for s in tool_specs(_cfg(enable_browser=False))}
    assert "browser" not in names
    assert "session" in names  # others still present


def test_http_request_tool_passes_proxy_through():
    seen = {}

    class _ProxyHttp:
        def request(self, method, url, headers=None, body=None, timeout=20.0, auth=None, proxy=None):
            seen["proxy"] = proxy
            return {"status": 200, "headers": {}, "body": "ok"}

    ex = _ex(http=_ProxyHttp())
    ex.execute("http_request", {"method": "GET", "url": "http://inner/x", "proxy": "127.0.0.1:1080"})
    assert seen["proxy"] == "127.0.0.1:1080"

import socket
import time

from harness.sessions import PTYSession, ReverseShellListener, SessionManager, SocketSession


def test_pty_session_runs_and_persists_state():
    mgr = SessionManager()
    mgr.open("s")
    try:
        out = mgr.send("s", "echo hi", timeout=3.0)
        assert "hi" in out
        mgr.send("s", "X=42", timeout=2.0)
        out2 = mgr.send("s", "echo value=$X", timeout=2.0)
        assert "value=42" in out2  # state persisted across sends
    finally:
        mgr.close_all()


def test_socket_session_roundtrip():
    a, b = socket.socketpair()
    sess = SocketSession(a)
    b.sendall(b"hello from peer\n")
    assert "hello from peer" in sess.read(timeout=2.0)
    sess.send("ping")
    assert b.recv(1024).startswith(b"ping")
    sess.close()
    b.close()


def test_reverse_shell_listener_catches_and_registers_session():
    mgr = SessionManager()
    listener = ReverseShellListener(mgr, session_name="revshell")
    listener.start(port=0)  # ephemeral; the payload uses listener.port
    try:
        client = socket.create_connection(("127.0.0.1", listener.port), timeout=2.0)
        deadline = time.monotonic() + 2.0
        while not listener.status()["caught"] and time.monotonic() < deadline:
            time.sleep(0.02)
        assert listener.status()["caught"] is True
        assert "revshell" in mgr.list()
        client.sendall(b"whoami-output\n")
        assert "whoami-output" in mgr.read("revshell", timeout=2.0)
        client.close()
    finally:
        listener.stop()
        mgr.close_all()

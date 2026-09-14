"""Persistent interactive sessions — the capability a one-shot shell cannot provide.

A Session is anything you can send bytes to and read bytes from over time: a bash
shell on a PTY (holds cd/env/a foothold), a caught reverse shell (a socket), or a
persistent interpreter. The SessionManager keeps them by name for the run.
"""
from __future__ import annotations

import os
import pty
import select
import socket
import subprocess
import threading
import time


def _drain(read_fd_or_sock, is_socket: bool, timeout: float) -> str:
    """Read whatever is available until `timeout`, returning early after a quiet gap
    once some output has arrived. Good enough for command output over a tty/socket."""
    out = b""
    end = time.monotonic() + timeout
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([read_fd_or_sock], [], [], min(0.2, remaining))
        if ready:
            try:
                if is_socket:
                    chunk = read_fd_or_sock.recv(65536)
                else:
                    chunk = os.read(read_fd_or_sock, 65536)
            except (OSError, BlockingIOError):
                break
            if not chunk:
                break
            out += chunk
        elif out:
            break  # a quiet gap after real output — the command likely finished
    return out.decode(errors="replace")


class PTYSession:
    def __init__(self, cmd: list[str] | None = None, env: dict | None = None) -> None:
        self.master_fd, slave_fd = pty.openpty()
        self.proc = subprocess.Popen(
            cmd or ["bash"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            start_new_session=True,
            env=env,
            close_fds=True,
        )
        os.close(slave_fd)

    def send(self, data: str) -> None:
        if not data.endswith("\n"):
            data += "\n"
        os.write(self.master_fd, data.encode())

    def read(self, timeout: float = 2.0) -> str:
        return _drain(self.master_fd, is_socket=False, timeout=timeout)

    def close(self) -> None:
        try:
            self.proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass


class SocketSession:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.sock.setblocking(False)

    def send(self, data: str) -> None:
        if not data.endswith("\n"):
            data += "\n"
        self.sock.sendall(data.encode())

    def read(self, timeout: float = 2.0) -> str:
        return _drain(self.sock, is_socket=True, timeout=timeout)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, object] = {}

    def open(self, name: str, cmd: list[str] | None = None, env: dict | None = None) -> None:
        if name not in self._sessions:
            self._sessions[name] = PTYSession(cmd=cmd, env=env)

    def register(self, name: str, session: object) -> None:
        self._sessions[name] = session

    def has(self, name: str) -> bool:
        return name in self._sessions

    def send(self, name: str, data: str, timeout: float = 2.0) -> str:
        session = self._sessions[name]
        session.send(data)
        return session.read(timeout)

    def read(self, name: str, timeout: float = 2.0) -> str:
        return self._sessions[name].read(timeout)

    def close(self, name: str) -> None:
        session = self._sessions.pop(name, None)
        if session is not None:
            session.close()

    def list(self) -> list[str]:
        return list(self._sessions)

    def close_all(self) -> None:
        for name in list(self._sessions):
            self.close(name)


class ReverseShellListener:
    """Binds a listener on the harness's IP; a caught connection becomes a named
    session the agent then drives. Reverse shells 'just work' in the same-network
    sealed cell."""

    def __init__(self, manager: SessionManager, session_name: str = "revshell") -> None:
        self.manager = manager
        self.session_name = session_name
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.port: int | None = None
        self.lhost: str | None = None
        self.caught = False

    def start(self, port: int, lhost: str = "0.0.0.0") -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((lhost, port))
        srv.listen(1)
        self._srv = srv
        self.port = srv.getsockname()[1]
        self.lhost = lhost
        self.caught = False
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        try:
            conn, _addr = self._srv.accept()  # type: ignore[union-attr]
        except OSError:
            return
        self.manager.register(self.session_name, SocketSession(conn))
        self.caught = True

    def status(self) -> dict:
        return {
            "listening": self._srv is not None,
            "lhost": self.lhost,
            "port": self.port,
            "caught": self.caught,
            "session": self.session_name,
        }

    def stop(self) -> None:
        if self._srv is not None:
            try:
                self._srv.close()
            finally:
                self._srv = None

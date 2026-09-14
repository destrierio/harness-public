"""A trivial interactive TCP service: it hands out the flag only when it receives
the `getflag` command, so capturing it requires holding a live session (nc), not a
one-shot request. Models a service the agent must interact with over a session."""
from __future__ import annotations

import socket
import threading


def make_tcp_service(port: int, flag: str) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)

    def handle(conn: socket.socket) -> None:
        try:
            conn.sendall(b"widget-service v1. commands: help, getflag\n")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                if b"getflag" in data:
                    conn.sendall((flag + "\n").encode())
                else:
                    conn.sendall(b"unknown command\n")
        except OSError:
            pass
        finally:
            conn.close()

    def serve() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv

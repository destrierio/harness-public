"""Client for the persistent Python kernel (harness/pykernel.py). Sends a code
block, returns its captured output. State persists across calls; a call that runs
past its timeout kills the kernel (it auto-restarts on the next call)."""
from __future__ import annotations

import base64
import os
import subprocess
import threading


class PythonKernel:
    def __init__(self, python: str = "python3") -> None:
        self._python = python
        self._repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.proc: subprocess.Popen | None = None
        self._start()

    def _start(self) -> None:
        env = {**os.environ, "PYTHONPATH": self._repo_root}
        self.proc = subprocess.Popen(
            [self._python, "-u", "-m", "harness.pykernel"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=self._repo_root,
            env=env,
        )

    def exec(self, code: str, timeout: float = 60.0) -> str:
        if self.proc is None or self.proc.poll() is not None:
            self._start()
        payload = base64.b64encode(code.encode()).decode()
        try:
            self.proc.stdin.write(f"__EXEC__ {payload}\n")  # type: ignore[union-attr]
            self.proc.stdin.flush()  # type: ignore[union-attr]
        except (BrokenPipeError, ValueError):
            return "python kernel is not running"
        return self._read_result(timeout)

    def _read_result(self, timeout: float) -> str:
        timed_out = {"hit": False}

        def kill():
            timed_out["hit"] = True
            try:
                self.proc.kill()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass

        timer = threading.Timer(timeout, kill)
        timer.start()
        started = False
        lines: list[str] = []
        clean_end = False
        try:
            for line in self.proc.stdout:  # type: ignore[union-attr]
                if line.strip() == "__BEGIN__":
                    started = True
                    continue
                if line.strip() == "__END__":
                    clean_end = True
                    break
                if started:
                    lines.append(line)
        finally:
            timer.cancel()
        if timed_out["hit"]:
            return f"python_exec timed out after {timeout:g}s (kernel restarted)"
        if not clean_end:
            return "python kernel ended unexpectedly: " + "".join(lines)
        return "".join(lines).rstrip("\n")

    def close(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
            except Exception:  # noqa: BLE001
                pass

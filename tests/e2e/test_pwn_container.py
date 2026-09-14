"""Gated container e2e: proves the pwn path (real pwntools + gdb + a compiled
ret2win binary) captures the flag on Linux. Skipped unless DH_DOCKER_E2E=1 and
docker is present, so the default offline suite needs no Docker."""
import json
import os
import shutil
import subprocess

import pytest

_GATED = os.environ.get("DH_DOCKER_E2E") == "1" and shutil.which("docker")
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.skipif(not _GATED, reason="set DH_DOCKER_E2E=1 (and have docker) to run the container pwn e2e")
def test_pwn_ret2win_capture_in_container():
    subprocess.run(
        ["docker", "build", "-f", "testrig/pwn/Dockerfile.e2e", "-t", "dh-pwn-e2e", "."],
        cwd=_ROOT, check=True,
    )
    out = subprocess.run(
        ["docker", "run", "--rm", "dh-pwn-e2e"],
        cwd=_ROOT, capture_output=True, text=True, check=True,
    )
    lines = [ln for ln in out.stdout.splitlines() if ln.startswith("PWN_E2E_RESULT")]
    assert lines, f"no result line in output:\n{out.stdout}"
    data = json.loads(lines[-1].split(" ", 1)[1])
    assert data["flags_captured"] == 1

"""In-image half of the capability gate: every PROMISED tool resolves on $PATH in
the built image. Gated like the other container e2e — set DH_DOCKER_E2E=1 and point
DH_IMAGE at a built image (default destrier-harness:local)."""
import os
import shutil
import subprocess

import pytest

from harness import audit

pytestmark = pytest.mark.skipif(
    os.environ.get("DH_DOCKER_E2E") != "1",
    reason="container e2e is gated behind DH_DOCKER_E2E=1",
)


def test_all_promised_tools_on_path_in_image():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    image = os.environ.get("DH_IMAGE", "destrier-harness:local")
    script = "; ".join(f'command -v {t} >/dev/null || echo MISSING:{t}' for t in audit.PROMISED_TOOLS)
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bash", image, "-lc", script],
        capture_output=True, text=True, timeout=120,
    )
    missing = [ln for ln in proc.stdout.splitlines() if ln.startswith("MISSING:")]
    assert not missing, f"promised tools absent from {image}: {missing}\nstderr:{proc.stderr[:400]}"


def test_promised_pymodules_importable_in_image():
    """Every promised python module (unicorn/capstone/pwn) imports in the built image —
    a missing wheel should fail here, not surface as an ImportError mid-run in a cell."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    image = os.environ.get("DH_IMAGE", "destrier-harness:local")
    script = "; ".join(
        f'python3 -c "import {m}" 2>/dev/null || echo MISSING:{m}'
        for m in audit.PROMISED_PYMODULES
    )
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bash", image, "-lc", script],
        capture_output=True, text=True, timeout=120,
    )
    missing = [ln for ln in proc.stdout.splitlines() if ln.startswith("MISSING:")]
    assert not missing, f"promised python modules absent from {image}: {missing}\nstderr:{proc.stderr[:400]}"


def test_r2dec_decompiler_plugin_loads_in_image():
    """r2dec is baked as a radare2 plugin (pseudo-C for opaque parsers). Prove `pdd`
    resolves inside radare2 rather than being an unknown command."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    image = os.environ.get("DH_IMAGE", "destrier-harness:local")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bash", image, "-lc",
         "r2 -N -q -c 'pdd?' /bin/ls 2>&1"],
        capture_output=True, text=True, timeout=120,
    )
    out = (proc.stdout + proc.stderr).lower()
    assert "unknown command" not in out, f"r2dec (pdd) not loaded in {image}:\n{out[:400]}"


def test_re_emulate_selftest_in_image():
    """The reversing helper's unicorn+capstone path actually works in the built image:
    emulate a hand-assembled validator and recover its frame fields. This is the
    end-to-end proof behind the protocol-reversing "emulate the validator" fast path."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    image = os.environ.get("DH_IMAGE", "destrier-harness:local")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bash", image, "-lc",
         "cd /app && python3 -m harness.re_emulate --selftest"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0 and "OK" in proc.stdout, (
        f"re_emulate selftest failed in {image}:\nstdout:{proc.stdout[-400:]}\n"
        f"stderr:{proc.stderr[-400:]}")


def test_win_race_selftest_in_image():
    """The baked TOCTOU driver's concurrency path works in the built image: shared memfd +
    mmap MAP_SHARED + fd via SCM_RIGHTS + a forked, CPU-pinned flipper actually beats a
    self-hosted check-then-commit daemon. The end-to-end proof behind the race-condition-toctou
    "run win_race" fast path — and that memfd_create/sched_setaffinity are present in-image."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    image = os.environ.get("DH_IMAGE", "destrier-harness:local")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bash", image, "-lc",
         "cd /app && python3 -m harness.win_race --selftest"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0 and "OK" in proc.stdout, (
        f"win_race selftest failed in {image}:\nstdout:{proc.stdout[-400:]}\n"
        f"stderr:{proc.stderr[-400:]}")

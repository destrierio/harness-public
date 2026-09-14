from harness.python_kernel import PythonKernel


def test_state_persists_across_calls():
    k = PythonKernel()
    try:
        assert k.exec("a = 5") == ""  # assignment prints nothing
        assert "10" in k.exec("print(a * 2)")  # 'a' survived
    finally:
        k.close()


def test_exception_is_captured_not_fatal():
    k = PythonKernel()
    try:
        out = k.exec("1/0")
        assert "ZeroDivisionError" in out
        assert "7" in k.exec("print(3 + 4)")  # kernel still alive after the error
    finally:
        k.close()


def test_stdlib_import_works():
    k = PythonKernel()
    try:
        assert "4.0" in k.exec("import math; print(math.sqrt(16))")
    finally:
        k.close()


def test_timeout_kills_and_recovers():
    k = PythonKernel()
    try:
        out = k.exec("import time; time.sleep(30)", timeout=1.0)
        assert "timed out" in out
        assert "9" in k.exec("print(4 + 5)")  # auto-restarted
    finally:
        k.close()

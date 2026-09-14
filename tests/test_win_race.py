"""win_race — the baked concurrency driver for a check-then-commit / double-fetch (TOCTOU)
race. Pure helpers (page/field construction) are unit-tested here; the concurrency mechanics
are proven end-to-end by selftest(), which stands up a self-hosted TOCTOU daemon and beats it.
The selftest uses the tmpfile-fd + thread fallback so it runs off-Linux too (memfd_create and
CPU affinity are Linux-only optimisations exercised in-image)."""
import socket

import pytest


def test_patch_field_writes_little_endian_value_at_offset():
    from harness.win_race import patch_field
    buf = bytearray(16)
    patch_field(buf, 4, 0x11223344, 4, "little")
    assert bytes(buf[4:8]) == b"\x44\x33\x22\x11"
    assert bytes(buf[0:4]) == b"\x00\x00\x00\x00"     # nothing else touched


def test_patch_field_writes_big_endian_value():
    from harness.win_race import patch_field
    buf = bytearray(8)
    patch_field(buf, 0, 0x11223344, 4, "big")
    assert bytes(buf[0:4]) == b"\x11\x22\x33\x44"


def test_build_page_fills_to_size_and_sets_the_field():
    from harness.win_race import build_page
    page = build_page(page_hex=None, page_size=4096, field_offset=12,
                      field_value=0xDEADBEEF, field_size=4, endian="little")
    assert len(page) == 4096
    assert page[12:16] == b"\xEF\xBE\xAD\xDE"


def test_build_page_from_hex_content_then_zero_pads_and_patches():
    from harness.win_race import build_page
    page = build_page(page_hex="aa" * 32, page_size=64, field_offset=8,
                      field_value=0x01020304, field_size=4, endian="little")
    assert len(page) == 64
    assert page[:8] == b"\xaa" * 8
    assert page[8:12] == b"\x04\x03\x02\x01"          # field patched over the supplied content
    assert page[32:] == b"\x00" * 32                  # zero-padded up to page_size


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs AF_UNIX sockets")
def test_win_race_selftest_beats_a_local_toctou_daemon():
    # The one that matters: run the real driver (shared page + fd passed via SCM_RIGHTS + a
    # background field-flipper + resubmit-until-accepted) against a self-hosted check-then-
    # commit daemon that reads the field, spins a window, re-reads it, and accepts only if it
    # flipped from PREVIEW to COMMIT. If this passes, the concurrency mechanics genuinely work.
    from harness.win_race import selftest
    assert selftest() is True


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs AF_UNIX sockets")
def test_win_race_selftest_sweeps_to_the_right_commit_value():
    # The model may not perfectly reverse the SECOND value (its read is often hidden behind a
    # skipped call). It should be able to hand win_race several candidates and let it sweep — it
    # still wins when the real value is among them, without perfect reversing.
    from harness.win_race import selftest
    ok = selftest(commits=[0x0BAD0001, 0x22222222, 0x0BAD0002], accept_commit=0x22222222)
    assert ok is True

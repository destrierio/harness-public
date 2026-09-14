"""Offline tests for the reversing helper (harness.re_emulate).

The unicorn/capstone execution only runs in-image (see the gated e2e selftest); here
we test the PURE logic that makes the tool correct: ELF PT_LOAD parsing, page-aligned
mapping, x86 sub-register canonicalisation, the compare-attribution that turns an
instruction trace into "input offset X is checked against immediate Y" (the frame the
example validator run never recovered), and the byte-flip differential over an injected evaluator.
No unicorn import is required to run these.
"""
import struct

from harness import re_emulate as re


# --- a hand-built ELF64 so parse/mapping have real bytes, no toolchain needed -------

def _elf64(segments, *, e_type=2, machine=0x3e):
    """segments: list of (vaddr, offset, filesz, memsz, flags). Returns ELF64 LE bytes
    with the given PT_LOAD program headers (contents zero-filled to cover offsets)."""
    ehsize, phentsize = 64, 56
    phoff = ehsize
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    phnum = len(segments)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, machine, 1, 0x0, phoff, 0x0, 0,
        ehsize, phentsize, phnum, 64, 0, 0,
    )
    phdrs = b""
    end = phoff + phnum * phentsize
    for (vaddr, offset, filesz, memsz, flags) in segments:
        phdrs += struct.pack("<IIQQQQQQ", 1, flags, offset, vaddr, vaddr, filesz, memsz, 0x1000)
        end = max(end, offset + filesz)
    headers_end = phoff + phnum * phentsize
    blob = bytearray(header + phdrs)
    if len(blob) < end:
        blob += b"\x00" * (end - len(blob))
    # cosmetic content fill — never clobber the ELF header/phdrs (the first PT_LOAD
    # legitimately maps from offset 0, which covers them)
    for i, (vaddr, offset, filesz, memsz, flags) in enumerate(segments):
        w0 = max(offset, headers_end)
        if w0 < offset + filesz:
            blob[w0:offset + filesz] = bytes([(0x40 + i) & 0xff]) * (offset + filesz - w0)
    return bytes(blob)


def test_parse_load_segments_reads_pt_load():
    data = _elf64([(0x400000, 0x0, 0x20, 0x1000, 5)])
    segs = re.parse_load_segments(data)
    assert len(segs) == 1
    s = segs[0]
    assert (s.vaddr, s.offset, s.filesz, s.memsz) == (0x400000, 0x0, 0x20, 0x1000)


def test_elf_is_pie_true_for_dyn_false_for_exec():
    assert re.elf_is_pie(_elf64([(0x0, 0x0, 0x10, 0x1000, 5)], e_type=3)) is True
    assert re.elf_is_pie(_elf64([(0x400000, 0x0, 0x10, 0x1000, 5)], e_type=2)) is False


def test_plan_mappings_page_aligns_and_writes_segment_bytes():
    data = _elf64([(0x400123, 0x40 + 56, 0x8, 0x1000, 5)])
    segs = re.parse_load_segments(data)
    maps = re.plan_mappings(data, segs, base=0, page=0x1000)
    assert len(maps) == 1
    addr, blob = maps[0]
    assert addr == 0x400000                      # page-aligned down from 0x400123
    assert len(blob) % 0x1000 == 0
    # the 8 file bytes land at the segment's in-page offset, rest zero-filled
    off = 0x400123 - 0x400000
    assert blob[off:off + 0x8] == data[0x40 + 56:0x40 + 56 + 0x8]
    assert blob[0:off] == b"\x00" * off


def test_plan_mappings_merges_overlapping_regions():
    # two segments in the same page must not produce overlapping unicorn maps
    data = _elf64([(0x400000, 0x200, 0x10, 0x400, 5), (0x400400, 0x300, 0x10, 0x400, 6)])
    segs = re.parse_load_segments(data)
    maps = re.plan_mappings(data, segs, base=0, page=0x1000)
    assert len(maps) == 1 and maps[0][0] == 0x400000


def test_plan_mappings_applies_pie_base():
    data = _elf64([(0x1000, 0x0, 0x10, 0x1000, 5)], e_type=3)
    segs = re.parse_load_segments(data)
    maps = re.plan_mappings(data, segs, base=0x555555554000, page=0x1000)
    assert maps[0][0] == 0x555555554000 + 0x1000


def test_canon_reg_folds_subregisters():
    assert re.canon_reg("eax") == re.canon_reg("rax") == re.canon_reg("al") == "rax"
    assert re.canon_reg("edi") == re.canon_reg("dil") == "rdi"
    assert re.canon_reg("r8d") == re.canon_reg("r8b") == "r8"


def _imm(v):
    return re.Operand(kind="imm", value=v)


def _reg(name, value=None):
    return re.Operand(kind="reg", reg=name, value=value)


def _mem(base, disp, value=None):
    return re.Operand(kind="mem", reg=base, disp=disp, value=value)


def test_extract_arg_compares_direct_memory_immediate():
    # cmp dword [rdi+0], 0x11223344   ->  (offset 0, imm 0x11223344)
    insns = [re.Insn(op="cmp", operands=(_mem("rdi", 0), _imm(0x11223344)))]
    assert re.extract_arg_compares(insns, arg_reg="rdi") == [(0, 0x11223344)]


def test_extract_arg_compares_through_register_load():
    # mov eax,[rdi+4]; cmp ax,0x7799  ->  (offset 4, imm 0x7799)
    insns = [
        re.Insn(op="mov", dst="eax", src_base="rdi", src_disp=4),
        re.Insn(op="cmp", operands=(_reg("ax"), _imm(0x7799))),
    ]
    assert re.extract_arg_compares(insns, arg_reg="rdi") == [(4, 0x7799)]


def test_extract_arg_compares_computed_constant_via_runtime_value():
    # mov eax,[rdi]; ...compute edx...; cmp eax,edx  where edx holds a COMPUTED magic.
    # No static immediate exists — the required value is edx's concrete runtime value,
    # captured by the emulator. This is the "computed/XOR'd magic" case.
    insns = [
        re.Insn(op="mov", dst="eax", src_base="rdi", src_disp=0),
        re.Insn(op="cmp", operands=(_reg("eax"), _reg("edx", value=0x7678))),
    ]
    assert re.extract_arg_compares(insns, arg_reg="rdi") == [(0, 0x7678)]


def test_extract_arg_compares_ignores_non_arg_and_clobbered():
    insns = [
        re.Insn(op="mov", dst="eax", src_base="rsi", src_disp=8),          # not the arg
        re.Insn(op="cmp", operands=(_reg("eax"), _imm(0xdead))),           # -> ignored
        re.Insn(op="mov", dst="ecx", src_base="rdi", src_disp=6),
        re.Insn(op="mov", dst="ecx"),                                      # clobbers ecx (no arg src)
        re.Insn(op="cmp", operands=(_reg("ecx"), _imm(0xbeef))),          # -> ignored (clobbered)
    ]
    assert re.extract_arg_compares(insns, arg_reg="rdi") == []


def test_extract_arg_compares_dedupes_preserving_order():
    insns = [
        re.Insn(op="cmp", operands=(_mem("rdi", 0), _imm(0xA))),
        re.Insn(op="cmp", operands=(_mem("rdi", 4), _imm(0xB))),
        re.Insn(op="cmp", operands=(_mem("rdi", 0), _imm(0xA))),  # duplicate
    ]
    assert re.extract_arg_compares(insns) == [(0, 0xA), (4, 0xB)]


# --- the byte-flip differential over an injected evaluator (no unicorn) -------------

def test_differential_flags_offset_whose_flip_changes_acceptance():
    # accept iff byte[2] == 0x99; every other offset is inert.
    def evaluate(buf):
        return re.EvalResult(accepted=(buf[2] == 0x99), compares=())
    report = re.differential(evaluate, length=4, probe_values=(0x00, 0x99, 0xff))
    assert report.gating_offsets() == [2]


def test_differential_flags_offset_that_unlocks_new_compares():
    # touching byte[0] doesn't flip acceptance but exposes a downstream compare
    # (a magic gate): the differential still marks the offset live.
    def evaluate(buf):
        if buf[0] == 0x41:
            return re.EvalResult(accepted=False, compares=(0x1234,))
        return re.EvalResult(accepted=False, compares=())
    report = re.differential(evaluate, length=3, probe_values=(0x00, 0x41))
    assert 0 in report.gating_offsets()


# --- double-fetch / TOCTOU race detection (the example validator ROOT failure mode) --------------
# The root gate is a check-then-commit RACE, not a constructible frame: the daemon reads
# one field, wants PREVIEW, then re-reads it and authorises on COMMIT. No static buffer
# holds both. These pin the detector that turns the emulator's misleading "needs a hash
# preimage" plateau into a correct "RACE — flip it concurrently" verdict.

def test_detect_double_fetch_flags_only_multi_constant_offsets():
    # offset 0 is compared against two constants (a re-read wanting different values);
    # offset 4 always wants the same value. Only offset 0 is a double-fetch.
    fields = [(0, 0x1111), (4, 0x99), (0, 0x2222), (4, 0x99)]
    assert re.detect_double_fetch(fields) == [(0, [0x1111, 0x2222])]


def test_detect_double_fetch_empty_when_each_offset_single_valued():
    assert re.detect_double_fetch([(0, 1), (4, 2), (6, 3)]) == []


def test_probe_double_fetch_reveals_a_staged_check_then_commit():
    # cold, only the FIRST required value shows (the validator rejects before the second
    # read); once that value is written, the re-read demands a DIFFERENT constant at the
    # SAME offset. probe_double_fetch must seed forward and surface both.
    A, B = 0xAAAAAAAA, 0xBBBBBBBB

    def oracle(buf: bytes):
        fields = [(0, A)]
        if buf[0:4] == struct.pack("<I", A):
            fields.append((0, B))       # re-read wants B -> never statically accepted
        return False, fields

    assert re.probe_double_fetch(oracle, length=8) == [(0, [A, B])]


def test_probe_double_fetch_ignores_a_normal_staged_validator():
    # a real staged frame (magic then command) has ONE value per offset — not a race.
    MAGIC, CMD = 0x12344321, 0x6231

    def oracle(buf: bytes):
        fields = [(0, MAGIC)]
        ok = False
        if buf[0:4] == struct.pack("<I", MAGIC):
            fields.append((4, CMD))
            ok = buf[4:6] == struct.pack("<H", CMD)
        return ok, fields

    assert re.probe_double_fetch(oracle, length=8) == []


def test_race_diagnosis_none_when_no_double_fetch():
    assert re.race_diagnosis([]) is None


def test_race_diagnosis_points_at_the_race_skill_and_field():
    msg = re.race_diagnosis([(0, [0xAAAAAAAA, 0xBBBBBBBB])])
    assert msg is not None
    assert "RACE" in msg
    assert "race-condition-toctou" in msg
    assert "+0x00" in msg


# --- the unicorn engine on non-flat validators (the real example validator failure mode) ---------
# These run the actual UnicornEvaluator, so they need the wheels; skipped when absent.
# The current engine emulates a function in ISOLATION with no call-skipping and no
# unmapped-memory handling, so example validator's 0x1000 (calls clock_gettime + 6 helpers) and
# 0x2000 (jump-table dispatcher) faulted early and returned garbage. These pin the fix.
import pytest  # noqa: E402

uni = pytest.importorskip("unicorn", reason="unicorn/capstone only in the built image")
pytest.importorskip("capstone", reason="unicorn/capstone only in the built image")

BASE = 0x400000


def _val_with_call_between_two_fields(magic: int, ver: int) -> bytes:
    """A validator that checks field@0, CALLS a helper at a far UNMAPPED address (like a
    clock_gettime/PLT stub), then checks field@4. Reaching the second check proves the
    call was skipped rather than faulting the whole emulation."""
    # layout (offsets from BASE): see rel computations below
    call_site, after_call = 0x09, 0x0e
    target = 0x900000                      # far, outside the single mapped page -> unmapped
    rel32 = (BASE + target) - (BASE + after_call)
    return bytes([
        0x8B, 0x07,                                 # 0x00 mov eax,[rdi]
        0x3D, *struct.pack("<I", magic),            # 0x02 cmp eax, magic
        0x75, 0x16,                                 # 0x07 jne fail (-> 0x1f)
        0xE8, *struct.pack("<i", rel32),            # 0x09 call <unmapped helper>
        0x8B, 0x4F, 0x04,                           # 0x0e mov ecx,[rdi+4]
        0x81, 0xF9, *struct.pack("<I", ver),        # 0x11 cmp ecx, ver
        0x75, 0x06,                                 # 0x17 jne fail (-> 0x1f)
        0xB8, 0x01, 0x00, 0x00, 0x00,               # 0x19 mov eax,1
        0xC3,                                       # 0x1e ret
        0x31, 0xC0,                                 # 0x1f fail: xor eax,eax
        0xC3,                                       # 0x21 ret
    ])


def test_engine_skips_a_call_to_an_unmapped_helper():
    magic, ver = 0x11223344, 0x55667788
    code = _val_with_call_between_two_fields(magic, ver)
    ev = re.UnicornEvaluator([(BASE, code.ljust(0x1000, b"\x00"))], BASE, arg_reg="rdi", length=8)
    good = struct.pack("<I", magic) + struct.pack("<I", ver)
    _accepted, trace = ev.run_once(good)
    fields = re.extract_arg_compares(trace, "rdi")
    assert (0, magic) in fields, "field before the call should be recovered"
    assert (4, ver) in fields, "field AFTER the call must be recovered — the call must be skipped, not faulted"


def test_engine_auto_maps_an_unmapped_data_read():
    magic = 0x0badf00d
    code = bytes([
        0x8B, 0x8F, 0x00, 0x00, 0x10, 0x00,         # 0x00 mov ecx,[rdi+0x100000]  (unmapped read)
        0x8B, 0x07,                                 # 0x06 mov eax,[rdi]
        0x3D, *struct.pack("<I", magic),            # 0x08 cmp eax, magic
        0x75, 0x06,                                 # 0x0d jne fail (-> 0x15)
        0xB8, 0x01, 0x00, 0x00, 0x00,               # 0x0f mov eax,1
        0xC3,                                       # 0x14 ret
        0x31, 0xC0,                                 # 0x15 fail: xor eax,eax
        0xC3,                                       # 0x17 ret
    ])
    ev = re.UnicornEvaluator([(BASE, code.ljust(0x1000, b"\x00"))], BASE, arg_reg="rdi", length=8)
    good = struct.pack("<I", magic) + b"\x00\x00\x00\x00"
    _accepted, trace = ev.run_once(good)
    fields = re.extract_arg_compares(trace, "rdi")
    assert (0, magic) in fields, "an unmapped data read must be auto-mapped, not fault the whole run"


def test_engine_still_accepts_a_flat_validator():
    # the original flat case must keep working unchanged
    magic = 0x41424344
    code = bytes([
        0x8B, 0x07,                                 # mov eax,[rdi]
        0x3D, *struct.pack("<I", magic),            # cmp eax, magic
        0x75, 0x06,                                 # jne fail
        0xB8, 0x01, 0x00, 0x00, 0x00,               # mov eax,1
        0xC3,                                       # ret
        0x31, 0xC0, 0xC3,                           # fail: xor eax,eax; ret
    ])
    ev = re.UnicornEvaluator([(BASE, code.ljust(0x1000, b"\x00"))], BASE, arg_reg="rdi", length=8)
    acc_good, _ = ev.run_once(struct.pack("<I", magic) + b"\x00\x00\x00\x00")
    acc_bad, _ = ev.run_once(b"\x00" * 8)
    assert acc_good is True and acc_bad is False


def test_engine_executes_a_mapped_internal_helper_call():
    # The measurement (0x1000 -> external/internal helpers) needs INTERNAL helper calls to actually
    # RUN — only external/PLT calls (clock_gettime) should be skipped. A helper mapped
    # inside the binary must execute, so a validator whose result comes from it is real.
    code = bytearray(0x80)
    code[0x00:0x05] = bytes([0xE8, *struct.pack("<i", 0x40 - 0x05)])  # call helper @ +0x40
    code[0x05] = 0xC3                                                 # ret
    code[0x40:0x46] = bytes([0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3])     # helper: mov eax,0x1337; ret
    ev = re.UnicornEvaluator([(BASE, bytes(code).ljust(0x1000, b"\x00"))], BASE, arg_reg="rdi", length=8)
    accepted, _ = ev.run_once(b"\x00" * 8)
    assert accepted is True   # helper ran -> RAX=0x1337; if it were skipped RAX=call_ret=0 -> False


# --- the constraint-propagation solver (pure: injected oracle, no unicorn) ------------

def test_solve_constructs_a_staged_frame():
    # A staged validator: accepts only when magic@0, version@4 (u16) and command@6 (u16)
    # are all correct, revealing each next required field only once the prior one is set —
    # exactly the frame the example validator admission needs constructed. The solver must converge.
    MAGIC, VER, CMD = 0x12344321, 0x0007, 0x1234

    def oracle(buf: bytes):
        fields = [(0, MAGIC)]
        if buf[0:4] == struct.pack("<I", MAGIC):
            fields.append((4, VER))
            if buf[4:6] == struct.pack("<H", VER):
                fields.append((6, CMD))
                if buf[6:8] == struct.pack("<H", CMD):
                    return True, fields
        return False, fields

    frame, ok = re.solve(oracle, length=8)
    assert ok is True
    assert frame[0:4] == struct.pack("<I", MAGIC)
    assert frame[4:6] == struct.pack("<H", VER)
    assert frame[6:8] == struct.pack("<H", CMD)


def test_solve_reports_failure_and_sets_known_fields_when_unsolvable():
    # A hash-gated accept the field solver cannot satisfy: it still returns the fixed
    # fields it DID recover (the magic prefix) and ok=False, rather than looping forever.
    MAGIC = 0x10203040

    def oracle(buf: bytes):
        return False, [(0, MAGIC)]   # magic always demanded, accept never granted

    frame, ok = re.solve(oracle, length=16, max_rounds=8)
    assert ok is False
    assert frame[0:4] == struct.pack("<I", MAGIC)   # the constructible part was still set


def test_solve_over_the_real_engine_cracks_a_staged_validator_with_a_helper():
    # End-to-end, the example validator shape: magic@0, then an INTERNAL helper computes the required
    # version, checked against version@4. The engine must RUN the helper (so the computed
    # constant is recovered) and solve() must construct the accepting frame from it.
    MAGIC, VER = 0x12344321, 0x1207
    code = bytearray(0x80)
    code[0x00:0x02] = bytes([0x8B, 0x07])                       # mov eax,[rdi]
    code[0x02:0x07] = bytes([0x3D, *struct.pack("<I", MAGIC)])  # cmp eax, MAGIC
    code[0x07:0x09] = bytes([0x75, 0x14])                       # jne fail (-> 0x1d)
    code[0x09:0x0e] = bytes([0xE8, *struct.pack("<i", 0x40 - 0x0e)])  # call helper @ +0x40
    code[0x0e:0x12] = bytes([0x0F, 0xB7, 0x4F, 0x04])           # movzx ecx,word [rdi+4]
    code[0x12:0x14] = bytes([0x39, 0xC1])                       # cmp ecx, eax   (eax = helper's VER)
    code[0x14:0x16] = bytes([0x75, 0x07])                       # jne fail (-> 0x1d)
    code[0x16:0x1b] = bytes([0xB8, 0x01, 0x00, 0x00, 0x00])     # mov eax,1
    code[0x1b] = 0xC3                                           # ret
    code[0x1d:0x20] = bytes([0x31, 0xC0, 0xC3])                 # fail: xor eax,eax; ret
    code[0x40:0x46] = bytes([0xB8, *struct.pack("<I", VER), 0xC3])  # helper: mov eax,VER; ret

    ev = re.UnicornEvaluator([(BASE, bytes(code).ljust(0x1000, b"\x00"))], BASE, arg_reg="rdi", length=8)

    def oracle(buf: bytes):
        acc, tr = ev.run_once(buf)
        return acc, re.extract_arg_compares(tr, "rdi")

    frame, ok = re.solve(oracle, length=8)
    assert ok is True
    assert frame[0:4] == struct.pack("<I", MAGIC)
    assert frame[4:6] == struct.pack("<H", VER)


def test_engine_detects_a_double_fetch_when_both_reads_are_on_one_trace():
    # The same field read twice, compared against two different constants on a straight
    # path (both cmps execute cold). The engine + detector must FLAG the race.
    ma, mb = 0x11111111, 0x22222222
    code = bytes([
        0x8B, 0x07, 0x3D, *struct.pack("<I", ma),   # mov eax,[rdi]; cmp eax, MODE_A
        0x8B, 0x07, 0x3D, *struct.pack("<I", mb),   # mov eax,[rdi]; cmp eax, MODE_B
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,          # mov eax,1; ret
    ])
    ev = re.UnicornEvaluator([(BASE, code.ljust(0x1000, b"\x00"))], BASE, arg_reg="rdi", length=8)
    _acc, trace = ev.run_once(b"\x00" * 8)
    df = re.detect_double_fetch(re.extract_arg_compares(trace, "rdi"))
    assert df and df[0][0] == 0 and set(df[0][1]) == {ma, mb}
    assert "race-condition-toctou" in (re.race_diagnosis(df) or "")


def test_engine_probe_reveals_a_STAGED_double_fetch_the_staged_gate_shape():
    # The exact example validator root gate: reject unless field@0 == MODE_A (the PREVIEW check), THEN
    # re-read field@0 and accept only if it now reads MODE_B (the COMMIT). Cold, only
    # MODE_A shows; probe_double_fetch must seed it, reach the re-read, and report the race
    # — while solve() can NEVER statically accept it. This is the pipeline the run needs.
    ma, mb = 0x11111111, 0x22222222
    code = bytearray(0x40)
    code[0x00:0x02] = bytes([0x8B, 0x07])                     # mov eax,[rdi]
    code[0x02:0x07] = bytes([0x3D, *struct.pack("<I", ma)])   # cmp eax, MODE_A
    code[0x07:0x09] = bytes([0x75, 0x0f])                     # jne fail (-> 0x18)
    code[0x09:0x0b] = bytes([0x8B, 0x07])                     # mov eax,[rdi]   (re-read)
    code[0x0b:0x10] = bytes([0x3D, *struct.pack("<I", mb)])   # cmp eax, MODE_B
    code[0x10:0x12] = bytes([0x75, 0x06])                     # jne fail (-> 0x18)
    code[0x12:0x17] = bytes([0xB8, 0x01, 0x00, 0x00, 0x00])   # mov eax,1
    code[0x17] = 0xC3                                         # ret (accept)
    code[0x18:0x1a] = bytes([0x31, 0xC0])                     # fail: xor eax,eax
    code[0x1a] = 0xC3                                         # ret
    ev = re.UnicornEvaluator([(BASE, bytes(code).ljust(0x1000, b"\x00"))], BASE,
                             arg_reg="rdi", length=8)

    def oracle(buf: bytes):
        acc, tr = ev.run_once(buf)
        return acc, re.extract_arg_compares(tr, "rdi")

    _a0, cold = oracle(b"\x00" * 8)
    assert (0, ma) in cold and (0, mb) not in cold        # cold hides the second read
    df = re.probe_double_fetch(oracle, length=8)
    assert df and df[0][0] == 0 and set(df[0][1]) == {ma, mb}
    _frame, ok = re.solve(oracle, length=8)
    assert ok is False                                    # no static buffer wins the race

"""Emulate one validator/parser function and read the frame it demands.

The example validator failure mode: an obfuscated (control-flow-flattened) parser is HAND-READ,
the flattener's dispatcher constants are mistaken for command opcodes, and the run is
spent fuzzing the opcode space. The one move that cracks it is running just the
validator function under emulation and watching which INPUT offset it compares against
which immediate — magic@0 / version@4 / command@6 fall out in seconds. This tool does
that so the model does not hand-roll fragile unicorn glue under a clock.

Two layers, split for testability:
  * PURE logic (no unicorn/capstone) — ELF PT_LOAD parsing, page-aligned mapping,
    x86 sub-register canonicalisation, compare-attribution over an instruction trace,
    and the byte-flip differential over an injected evaluator. Unit-tested offline.
  * The unicorn+capstone engine (`UnicornEvaluator`) and the CLI — only meaningful in
    the built image where the wheels are baked. `--selftest` proves it end to end there.

CLI:
    python3 -m harness.re_emulate ./bin --start 0x1189 --end 0x1240
    python3 -m harness.re_emulate ./bin --start 0x1189 --len 32 --diff
    python3 -m harness.re_emulate --selftest
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- ELF

_ELF_MAGIC = b"\x7fELF"
_PT_LOAD = 1
_ET_DYN = 3


@dataclass
class Segment:
    vaddr: int
    offset: int
    filesz: int
    memsz: int
    flags: int


def _u(data: bytes, fmt: str, off: int) -> int:
    return struct.unpack_from(fmt, data, off)[0]


def _check_elf(data: bytes) -> None:
    if len(data) < 20 or data[:4] != _ELF_MAGIC:
        raise ValueError("not an ELF file")


def elf_class(data: bytes) -> int:
    """32 or 64 (EI_CLASS)."""
    _check_elf(data)
    return 64 if data[4] == 2 else 32


def elf_is_pie(data: bytes) -> bool:
    """True for ET_DYN (PIE / shared object) — the load base is not fixed."""
    _check_elf(data)
    return _u(data, "<H", 16) == _ET_DYN


def parse_load_segments(data: bytes) -> list[Segment]:
    """Every PT_LOAD program header, for both ELF32 and ELF64 little-endian."""
    _check_elf(data)
    segs: list[Segment] = []
    if elf_class(data) == 64:
        phoff, phentsize, phnum = _u(data, "<Q", 32), _u(data, "<H", 54), _u(data, "<H", 56)
        for i in range(phnum):
            b = phoff + i * phentsize
            if _u(data, "<I", b) != _PT_LOAD:
                continue
            segs.append(Segment(
                vaddr=_u(data, "<Q", b + 16), offset=_u(data, "<Q", b + 8),
                filesz=_u(data, "<Q", b + 32), memsz=_u(data, "<Q", b + 40),
                flags=_u(data, "<I", b + 4),
            ))
    else:
        phoff, phentsize, phnum = _u(data, "<I", 28), _u(data, "<H", 42), _u(data, "<H", 44)
        for i in range(phnum):
            b = phoff + i * phentsize
            if _u(data, "<I", b) != _PT_LOAD:
                continue
            segs.append(Segment(
                vaddr=_u(data, "<I", b + 8), offset=_u(data, "<I", b + 4),
                filesz=_u(data, "<I", b + 16), memsz=_u(data, "<I", b + 20),
                flags=_u(data, "<I", b + 24),
            ))
    return segs


def align_down(x: int, page: int) -> int:
    return x - (x % page)


def align_up(x: int, page: int) -> int:
    return align_down(x + page - 1, page)


def plan_mappings(data: bytes, segments: list[Segment], *, base: int = 0,
                  page: int = 0x1000) -> list[tuple[int, bytes]]:
    """Non-overlapping, page-aligned (addr, bytes) regions to hand unicorn. Each
    PT_LOAD's file bytes are placed at its in-region offset (base-relative for PIE),
    the rest zero-filled; regions in the same/overlapping pages are merged so unicorn
    never sees an overlapping map (which it rejects)."""
    raw: list[list] = []
    for s in segments:
        va = base + s.vaddr
        start = align_down(va, page)
        end = align_up(va + max(s.memsz, s.filesz, 1), page)
        raw.append([start, end, [(va, data[s.offset:s.offset + s.filesz])]])
    raw.sort(key=lambda r: r[0])
    merged: list[list] = []
    for r in raw:
        if merged and r[0] <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], r[1])
            merged[-1][2].extend(r[2])
        else:
            merged.append(r)
    out: list[tuple[int, bytes]] = []
    for start, end, writes in merged:
        buf = bytearray(end - start)
        for addr, chunk in writes:
            o = addr - start
            buf[o:o + len(chunk)] = chunk
        out.append((start, bytes(buf)))
    return out


# ------------------------------------------------------ register canonicalisation

def _build_canon() -> dict[str, str]:
    m: dict[str, str] = {}
    for base, parts in {
        "rax": ("rax", "eax", "ax", "al", "ah"),
        "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
        "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
        "rdx": ("rdx", "edx", "dx", "dl", "dh"),
        "rsi": ("rsi", "esi", "si", "sil"),
        "rdi": ("rdi", "edi", "di", "dil"),
        "rbp": ("rbp", "ebp", "bp", "bpl"),
        "rsp": ("rsp", "esp", "sp", "spl"),
    }.items():
        for p in parts:
            m[p] = base
    for n in range(8, 16):
        b = f"r{n}"
        for suf in ("", "d", "w", "b"):
            m[f"{b}{suf}"] = b
    return m


_CANON = _build_canon()


def canon_reg(name: str | None) -> str | None:
    """Fold an x86 sub-register onto its 64-bit parent so `mov eax,[rdi+4]` then
    `cmp ax,imm` attribute to the same register. Unknown names pass through."""
    if not name:
        return name
    n = name.lower().lstrip("%")
    return _CANON.get(n, n)


# ---------------------------------------------------- compare attribution (core)

@dataclass
class Operand:
    """One compare operand. `value` is the CONCRETE value at execution time — known
    statically for an immediate, filled from the emulator for a register/memory operand
    (that is what lets a COMPUTED/XOR'd magic be recovered, not just a literal)."""
    kind: str                    # 'imm' | 'reg' | 'mem'
    reg: str | None = None       # register (kind 'reg') or base register (kind 'mem')
    disp: int = 0                # displacement (kind 'mem')
    value: int | None = None


@dataclass
class Insn:
    """A normalised instruction — the small shape the attributor needs, decoupled from
    capstone so the attribution logic is testable without it. A load records dst<-src;
    a cmp/test records its operands (with runtime values)."""
    op: str
    dst: str | None = None       # register written (any writing insn, so tracking clobbers)
    src_base: str | None = None  # for a load: base register of the [base+disp] source
    src_disp: int | None = None
    operands: tuple[Operand, ...] = ()   # for cmp/test


_LOAD_OPS = {"mov", "movzx", "movsx", "movsxd"}
_CMP_OPS = {"cmp", "test"}


def extract_arg_compares(insns: list[Insn], arg_reg: str = "rdi") -> list[tuple[int, int]]:
    """(input_offset, required_value) for every point the trace compares a byte/word/
    dword of the argument buffer against a constant — directly (`cmp [rdi+off], imm`),
    via a register just loaded from it (`mov eax,[rdi+off]; cmp ax,imm`), OR against a
    register holding a COMPUTED constant (`cmp eax,edx` -> edx's runtime value). These
    ARE the frame's fields and their required values. Deduped, in first-seen order."""
    arg = canon_reg(arg_reg)
    reg_of: dict[str, int] = {}   # canon reg -> arg offset it currently holds
    out: list[tuple[int, int]] = []
    for ins in insns:
        op = ins.op.lower()
        if op in _CMP_OPS:
            arg_off = const_val = None
            for o in ins.operands:
                is_arg = ((o.kind == "mem" and canon_reg(o.reg) == arg)
                          or (o.kind == "reg" and canon_reg(o.reg) in reg_of))
                if is_arg and arg_off is None:
                    arg_off = o.disp if o.kind == "mem" else reg_of[canon_reg(o.reg)]
                elif not is_arg and o.value is not None and const_val is None:
                    const_val = o.value
            if arg_off is not None and const_val is not None:
                pair = (arg_off, const_val)
                if pair not in out:
                    out.append(pair)
            continue
        if ins.dst is not None:
            w = canon_reg(ins.dst)
            if (op in _LOAD_OPS and ins.src_base is not None
                    and canon_reg(ins.src_base) == arg and ins.src_disp is not None):
                reg_of[w] = ins.src_disp
            else:
                reg_of.pop(w, None)   # clobbered by a non-arg write
    return out


# ------------------------------------------------------- byte-flip differential

@dataclass
class EvalResult:
    accepted: bool
    compares: tuple[int, ...] = ()


@dataclass
class DiffReport:
    length: int
    baseline: EvalResult
    per_offset: list[dict] = field(default_factory=list)

    def gating_offsets(self) -> list[int]:
        return [p["offset"] for p in self.per_offset if p["gating"]]


def differential(evaluate, length: int, *, seed: bytes | None = None,
                 probe_values: tuple[int, ...] = (0x00, 0xff, 0x41, 0x01)) -> DiffReport:
    """Flip each input byte in turn and watch the validator. An offset is LIVE if a
    flip changes acceptance OR the set of comparisons reached (a magic gate exposes a
    new compare without yet accepting). `evaluate(bytes)->EvalResult` is injected, so
    this is unit-testable without unicorn and reusable for any emulator."""
    buf = bytearray(seed if seed is not None else bytes(length))
    if len(buf) < length:
        buf += bytes(length - len(buf))
    base = evaluate(bytes(buf))
    base_cmp = set(base.compares)
    per: list[dict] = []
    for i in range(length):
        orig = buf[i]
        live = False
        cands: set[int] = set()
        for v in probe_values:
            if v == orig:
                continue
            buf[i] = v
            r = evaluate(bytes(buf))
            if r.accepted != base.accepted or set(r.compares) != base_cmp:
                live = True
            cands |= set(r.compares) - base_cmp
        buf[i] = orig
        per.append({"offset": i, "gating": live, "candidates": sorted(cands)})
    return DiffReport(length=length, baseline=base, per_offset=per)


def solve(evaluate_fields, length: int, *, seed: bytes | None = None,
          max_rounds: int = 24) -> tuple[bytes, bool]:
    """Construct an accepting input by CONSTRAINT PROPAGATION over the validator's own
    field checks. `evaluate_fields(bytes) -> (accepted, [(offset, required_value), ...])`
    returns whether the candidate is accepted and every input-offset/constant the run
    compared (from extract_arg_compares). Each round writes those required values into the
    buffer; setting an early gate (magic) lets the emulation reach and reveal the next one
    (version, command, a computed dword), so a STAGED validator converges to an accepting
    frame in a handful of rounds. Returns (constructed_bytes, accepted). When the accept is
    gated by something no field-compare exposes (a whole-buffer hash), it plateaus and
    returns the best frame with accepted=False — the fixed fields (e.g. the magic prefix)
    are still set, which is the constructible part. Pure: the oracle is injected, so this
    is unit-tested without unicorn."""
    buf = bytearray(seed if seed is not None else bytes(length))
    if len(buf) < length:
        buf += bytes(length - len(buf))
    for _ in range(max_rounds):
        accepted, fields = evaluate_fields(bytes(buf))
        if accepted:
            return bytes(buf), True
        changed = False
        for off, val in fields:
            if 0 <= off < length:
                width = min(4, length - off)
                chunk = (val & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
                if bytes(buf[off:off + width]) != chunk:
                    buf[off:off + width] = chunk
                    changed = True
        if not changed:
            break     # a fixed point that still is not accepted -> not field-solvable
    accepted, _ = evaluate_fields(bytes(buf))
    return bytes(buf), accepted


# --------------------------------------------------- double-fetch / TOCTOU race detect

def detect_double_fetch(fields: list[tuple[int, int]]) -> list[tuple[int, list[int]]]:
    """Offsets the validator compares against TWO OR MORE DISTINCT constants — the
    signature of a check-then-commit / double-fetch TOCTOU race: it reads that field
    more than once and demands a DIFFERENT value at each read, so no single static
    buffer can satisfy it. `fields` is extract_arg_compares output (best unioned across
    seeds via probe_double_fetch, since a staged check hides its second read behind its
    first). Returns [(offset, [sorted distinct constants]), ...] in first-seen order.
    Pure — the constants are whatever the emulated binary compared, never hardcoded."""
    by_off: dict[int, list[int]] = {}
    order: list[int] = []
    for off, val in fields:
        if off not in by_off:
            by_off[off] = []
            order.append(off)
        if val not in by_off[off]:
            by_off[off].append(val)
    return [(off, sorted(by_off[off])) for off in order if len(by_off[off]) >= 2]


def probe_double_fetch(evaluate_fields, length: int, *, seed: bytes | None = None,
                       max_rounds: int = 24) -> list[tuple[int, list[int]]]:
    """Drive the validator like `solve()` but ACCUMULATE every (offset, constant) it
    compares across rounds, then report double-fetch offsets. This is what makes race
    detection reliable rather than lucky: cold, a staged gate only exposes a field's
    FIRST required value (it branches to reject before the second read); writing that
    value lets the emulation reach a SECOND compare of the SAME offset against a
    DIFFERENT constant. Returns detect_double_fetch(union). Pure — oracle injected."""
    buf = bytearray(seed if seed is not None else bytes(length))
    if len(buf) < length:
        buf += bytes(length - len(buf))
    seen: list[tuple[int, int]] = []
    for _ in range(max_rounds):
        accepted, fields = evaluate_fields(bytes(buf))
        for pair in fields:
            if pair not in seen:
                seen.append(pair)
        if accepted:
            break
        changed = False
        for off, val in fields:
            if 0 <= off < length:
                width = min(4, length - off)
                chunk = (val & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
                if bytes(buf[off:off + width]) != chunk:
                    buf[off:off + width] = chunk
                    changed = True
        if not changed:
            break
    return detect_double_fetch(seen)


def race_diagnosis(double_fetch: list[tuple[int, list[int]]]) -> str | None:
    """A model-actionable RACE verdict from detect_double_fetch output, or None if the
    validator is not a double-fetch. Names the field and the values it demands (read
    from the binary), says WHY no static buffer wins, and points at the exploit."""
    if not double_fetch:
        return None
    lines = ["RACE (double-fetch / TOCTOU) — NOT statically solvable."]
    for off, vals in double_fetch:
        joined = " and ".join(f"{v:#x}" for v in vals)
        lines.append(f"  field [+{off:#04x}] is required to equal {joined} at different reads.")
    lines += [
        "  The validator re-reads this field and demands different values, so no static",
        "  buffer satisfies it; emulation is single-threaded over static memory and cannot",
        "  reveal or solve a race. Win it CONCURRENTLY: put the buffer in shared memory",
        "  (memfd_create + mmap MAP_SHARED), submit it, and flip the field between those",
        "  values from a background writer until the daemon accepts.",
        "  consult_skill 'race-condition-toctou'.",
    ]
    return "\n".join(lines)


# ------------------------------------------------ unicorn+capstone engine (in-image)

# arch -> (uc_arch, uc_mode, cs_arch, cs_mode, arg_reg_default, bits)
_ARCH = {
    "x86-64": ("X86", "64", "X86", "64", "rdi", 64),
    "x86": ("X86", "32", "X86", "32", "esp", 32),  # 32-bit passes args on the stack
}


def _reg_value(uc, name: str | None):
    """Concrete value of a register from the live emulator, or None."""
    if not name:
        return None
    from unicorn import x86_const as X
    try:
        return uc.reg_read(getattr(X, f"UC_X86_REG_{name.upper()}"))
    except Exception:  # noqa: BLE001 — an unknown/segment reg must not abort the hook
        return None


def _mem_value(uc, ci, o):
    """Concrete value at a memory operand's effective address (base+index*scale+disp)."""
    try:
        ea = o.mem.disp
        if o.mem.base:
            ea += _reg_value(uc, ci.reg_name(o.mem.base)) or 0
        if o.mem.index:
            ea += (_reg_value(uc, ci.reg_name(o.mem.index)) or 0) * o.mem.scale
        return int.from_bytes(uc.mem_read(ea & (2**64 - 1), o.size or 8), "little")
    except Exception:  # noqa: BLE001
        return None


def _call_target(ci, uc, bits: int) -> int | None:
    """Resolve a `call`'s target address: the absolute immediate for a direct call
    (`call 0x1234`), the register value for `call rax`, or the pointer stored at the
    memory operand for `call [rip+x]` / `call [rax]` (a GOT/PLT indirect). None when it
    cannot be resolved. Used to decide external (unmapped -> skip) vs internal (run)."""
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    if not ci.operands:
        return None
    o = ci.operands[0]
    mask = (1 << bits) - 1
    if o.type == X86_OP_IMM:
        return o.imm & mask
    if o.type == X86_OP_REG:
        v = _reg_value(uc, ci.reg_name(o.reg))
        return None if v is None else v & mask
    if o.type == X86_OP_MEM:
        v = _mem_value(uc, ci, o)   # value stored at the effective address = the target
        return None if v is None else v & mask
    return None


def _decode_insn(ci, uc) -> Insn:
    """capstone instruction + live emulator -> normalised Insn. For a cmp/test, each
    operand carries its CONCRETE value (immediate, or register/memory read from `uc`),
    so a computed constant is recoverable. For any other instruction, record the written
    register (so arg-tracking clobbers) and, for a load, the [arg+disp] source. In-image
    only (needs capstone detail=True)."""
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    mn = ci.mnemonic
    if mn in _CMP_OPS:
        ops: list[Operand] = []
        for o in ci.operands:
            if o.type == X86_OP_IMM:
                ops.append(Operand("imm", value=o.imm & ((1 << ((o.size or 4) * 8)) - 1)))
            elif o.type == X86_OP_REG:
                name = ci.reg_name(o.reg)
                ops.append(Operand("reg", reg=name, value=_reg_value(uc, name)))
            elif o.type == X86_OP_MEM:
                base = ci.reg_name(o.mem.base) if o.mem.base else None
                ops.append(Operand("mem", reg=base, disp=o.mem.disp, value=_mem_value(uc, ci, o)))
        return Insn(op=mn, operands=tuple(ops))
    dst = src_base = src_disp = None
    try:
        _read, written = ci.regs_access()
        if written:
            dst = ci.reg_name(written[0])
    except Exception:  # noqa: BLE001
        pass
    ops = ci.operands
    if mn in _LOAD_OPS and len(ops) >= 2:
        if ops[0].type == X86_OP_REG:
            dst = ci.reg_name(ops[0].reg)
        if ops[1].type == X86_OP_MEM and ops[1].mem.base:
            src_base = ci.reg_name(ops[1].mem.base)
            src_disp = ops[1].mem.disp
    return Insn(op=mn, dst=dst, src_base=src_base, src_disp=src_disp)


class UnicornEvaluator:
    """Runs one function over a candidate input and reports (accepted, trace). Built
    from pre-planned (addr,bytes) maps so `plan_mappings` stays pure and tested. Fresh
    unicorn state per call — no cross-run contamination."""

    def __init__(self, mappings: list[tuple[int, bytes]], start: int, end: int = 0, *,
                 arch: str = "x86-64", arg_reg: str | None = None, length: int = 16,
                 frame_addr: int = 0xb00000, stack_addr: int = 0x900000,
                 accept: int | None = None, max_insns: int = 500000,
                 skip_calls: bool = True, call_ret: int = 0) -> None:
        if arch not in _ARCH:
            raise ValueError(f"unsupported arch {arch!r}; try one of {sorted(_ARCH)} "
                             "(foreign-arch: run under qemu-<arch>-static instead)")
        self.mappings = mappings
        self.start, self.end = start, end
        self.arch = arch
        self.length = length
        self.frame_addr, self.stack_addr = frame_addr, stack_addr
        self.accept, self.max_insns = accept, max_insns
        # skip_calls: a real validator is not flat — it calls helpers (an internal check,
        # or clock_gettime/strtoul via the PLT). Emulated in isolation those calls recurse
        # or fault on an unmapped PLT stub, so the run dies before reaching the input
        # compares. Skipping every `call` (leaving RSP balanced, RAX <- call_ret) lets the
        # function flow through to its field checks. This is what makes example validator's 0x1000 /
        # 0x2000 emulatable at all. call_ret is the value the skipped helper "returns";
        # flip it to explore the other branch when a call return gates the path.
        self.skip_calls, self.call_ret = skip_calls, call_ret
        self.arg_reg = canon_reg(arg_reg) if arg_reg else _ARCH[arch][4]

    def run_once(self, input_bytes: bytes) -> tuple[bool, list[Insn]]:
        from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED,
                             UC_HOOK_MEM_WRITE_UNMAPPED, Uc, UcError)
        from unicorn import x86_const as X
        import unicorn as _uni
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

        _, uc_mode, _, _, _, bits = _ARCH[self.arch]
        mu = Uc(UC_ARCH_X86, getattr(_uni, f"UC_MODE_{uc_mode}"))
        for addr, blob in self.mappings:
            mu.mem_map(addr, len(blob))
            mu.mem_write(addr, blob)
        mu.mem_map(self.stack_addr, 0x100000)
        mu.mem_map(self.frame_addr, 0x1000)

        # Auto-map a zero page under any DATA read/write to an unmapped address — a global,
        # a heap pointer, a stack slot beyond what we reserved. Without this a single stray
        # access (common once helpers run) faults the whole emulation and RAX is garbage.
        # NB: only read/write, never FETCH — a fetch of unmapped code is the sentinel-ret
        # stop (or a genuinely bad jump) and must remain the signal to stop, not loop on a
        # zero page.
        def _map_unmapped(uc, _access, address, size, _value, _user):
            page = 0x1000
            base = address - (address % page)
            span = ((max(size, 1) + page - 1) // page + 1) * page
            try:
                uc.mem_map(base, span)
            except UcError:
                pass   # already mapped by a neighbouring fault — the retry is still safe
            return True   # retry the faulting access now that it is backed

        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, _map_unmapped)

        buf = bytes(input_bytes[:self.length]).ljust(self.length, b"\x00")
        mu.mem_write(self.frame_addr, buf)
        sp = self.stack_addr + 0x80000
        if bits == 64:
            mu.reg_write(X.UC_X86_REG_RSP, sp)
            mu.mem_write(sp, b"\x00" * 8)                       # sentinel return -> ret faults, we stop
            mu.reg_write(getattr(X, f"UC_X86_REG_{self.arg_reg.upper()}"), self.frame_addr)
        else:
            mu.reg_write(X.UC_X86_REG_ESP, sp)
            mu.mem_write(sp, b"\x00\x00\x00\x00")               # fake return addr
            mu.mem_write(sp + 4, struct.pack("<I", self.frame_addr))  # arg0 on the stack

        md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
        md.detail = True
        trace: list[Insn] = []
        pc_reg = X.UC_X86_REG_RIP if bits == 64 else X.UC_X86_REG_EIP
        ret_reg = X.UC_X86_REG_RAX if bits == 64 else X.UC_X86_REG_EAX

        def hook(uc, address, size, _user):
            try:
                code = uc.mem_read(address, size)
                first = None
                for ci in md.disasm(bytes(code), address):
                    trace.append(_decode_insn(ci, uc))
                    if first is None:
                        first = ci
                # Skip a call ONLY when its target is unmapped — an external/PLT stub or a
                # syscall thunk (clock_gettime, strtoul) that would fault. An INTERNAL helper
                # (target inside the mapped binary) is left to EXECUTE: it is the real logic
                # (example validator's measurement 0x1000 calls external/internal helpers — skipping those would make
                # the emulation meaningless). Skipping jumps past the call with RSP balanced
                # (no push, no matching pop) and hands call_ret back in RAX.
                if self.skip_calls and first is not None and first.mnemonic.startswith("call"):
                    target = _call_target(first, uc, bits)
                    external = True
                    if target is not None:
                        try:
                            uc.mem_read(target, 1)
                            external = False        # target is mapped -> an internal helper: run it
                        except UcError:
                            external = True
                    if external:
                        uc.reg_write(pc_reg, address + size)
                        uc.reg_write(ret_reg, self.call_ret & ((1 << bits) - 1))
            except Exception:  # noqa: BLE001 — a decode hiccup must never abort emulation
                pass

        mu.hook_add(UC_HOOK_CODE, hook)
        try:
            mu.emu_start(self.start, self.end, timeout=0, count=self.max_insns)
        except UcError:
            pass   # hitting the sentinel ret / running off the function is the normal stop
        rax = mu.reg_read(ret_reg)
        accepted = (rax == self.accept) if self.accept is not None else (rax != 0)
        return accepted, trace

    def __call__(self, input_bytes: bytes) -> EvalResult:
        accepted, trace = self.run_once(input_bytes)
        cmps = tuple(imm for _off, imm in extract_arg_compares(trace, self.arg_reg))
        return EvalResult(accepted=accepted, compares=cmps)


# ---------------------------------------------------------------- orchestration

def emulate(path: str, start: int, end: int = 0, *, length: int = 16, arch: str = "x86-64",
            arg_reg: str | None = None, base: int | None = None, accept: int | None = None,
            seed: bytes | None = None, skip_calls: bool = True,
            call_ret: int = 0) -> tuple[bool, list[tuple[int, int]], list[Insn]]:
    """Load an ELF, emulate [start,end) once over `seed`, and return
    (accepted, [(offset, immediate)...], full_trace). skip_calls/call_ret let a real
    (non-flat) validator run without diving into its helpers — see UnicornEvaluator."""
    data = open(path, "rb").read()
    segs = parse_load_segments(data)
    if base is None:
        base = 0x555555554000 if elf_is_pie(data) else 0
    maps = plan_mappings(data, segs, base=base)
    s = start + (base if elf_is_pie(data) else 0)
    e = (end + base) if (end and elf_is_pie(data)) else end
    ev = UnicornEvaluator(maps, s, e, arch=arch, arg_reg=arg_reg, length=length, accept=accept,
                          skip_calls=skip_calls, call_ret=call_ret)
    accepted, trace = ev.run_once(seed if seed is not None else bytes(length))
    return accepted, extract_arg_compares(trace, ev.arg_reg), trace


def selftest() -> None:
    """End-to-end proof the unicorn+capstone path works: emulate a hand-assembled
    validator whose two gates are (a) a LITERAL magic@0 and (b) a COMPUTED constant@4
    (`mov edx,imm; xor edx,imm; cmp ecx,edx` — no static immediate for the target).
    Assert the tool recovers BOTH offsets and required values, and the accept/reject
    verdict. Raises AssertionError on failure. Needs unicorn+capstone, so it runs in the
    gated in-image e2e, not the offline suite."""
    magic = 0x11223344
    ver = 0x00007678                 # == 0x00001000 ^ 0x00006678, never a literal in .text
    code = bytes([
        0x8B, 0x07,                                # 0x00 mov  eax,[rdi]
        0x3D, *struct.pack("<I", magic),           # 0x02 cmp  eax, magic
        0x75, 0x18,                                # 0x07 jne  fail (->0x21)
        0x8B, 0x4F, 0x04,                          # 0x09 mov  ecx,[rdi+4]
        0xBA, 0x00, 0x10, 0x00, 0x00,              # 0x0C mov  edx, 0x1000
        0x81, 0xF2, 0x78, 0x66, 0x00, 0x00,        # 0x11 xor  edx, 0x6678   -> edx = 0x7678
        0x39, 0xD1,                                # 0x17 cmp  ecx, edx       (computed target)
        0x75, 0x06,                                # 0x19 jne  fail (->0x21)
        0xB8, 0x01, 0x00, 0x00, 0x00,              # 0x1B mov  eax,1   (accept)
        0xC3,                                      # 0x20 ret
        0x31, 0xC0,                                # 0x21 fail: xor eax,eax
        0xC3,                                      # 0x23 ret
    ])
    BASE = 0x400000
    ev = UnicornEvaluator([(BASE, code.ljust(0x1000, b"\x00"))], BASE, arg_reg="rdi", length=8)

    good = struct.pack("<I", magic) + struct.pack("<I", ver)
    acc_good, trace = ev.run_once(good)
    fields = extract_arg_compares(trace, "rdi")
    assert acc_good is True, "validator should accept the correct frame"
    assert (0, magic) in fields, f"literal magic@0 not recovered: {[(o, hex(i)) for o, i in fields]}"
    assert (4, ver) in fields, f"computed field@4 not recovered: {[(o, hex(i)) for o, i in fields]}"

    acc_bad, _ = ev.run_once(b"\x00" * 8)
    assert acc_bad is False, "validator should reject a zero frame"

    # From an ACCEPTING seed, byte-flipping must show both gate fields as live (breaking
    # either one flips acceptance). Seeded this way because a single-byte flip cannot
    # satisfy a multi-byte magic from a cold/zero seed — that is what the structural
    # offset->constant extraction above is for.
    rep = differential(ev, length=8, seed=good, probe_values=(0x00, 0x44))
    gating = rep.gating_offsets()
    assert 0 in gating and 4 in gating, f"differential missed a gate field: {gating}"

    # A NON-FLAT validator — the real example validator shape: it CALLS a helper (like clock_gettime /
    # an internal check, here targeting an unmapped address) between two field checks. The
    # engine must skip the call and still reach the field AFTER it, or a real parser is
    # un-emulatable. This is the capability the 2026-09-12 fix added.
    magic2, ver2 = 0x0f1e2d3c, 0x00112233
    rel = 0x900000 - 0x0e                      # call at +0x09, next insn +0x0e, target far/unmapped
    code2 = bytes([
        0x8B, 0x07,                                 # 0x00 mov eax,[rdi]
        0x3D, *struct.pack("<I", magic2),           # 0x02 cmp eax, magic2
        0x75, 0x16,                                 # 0x07 jne fail (-> 0x1f)
        0xE8, *struct.pack("<i", rel),              # 0x09 call <unmapped helper>
        0x8B, 0x4F, 0x04,                           # 0x0e mov ecx,[rdi+4]
        0x81, 0xF9, *struct.pack("<I", ver2),       # 0x11 cmp ecx, ver2
        0x75, 0x06,                                 # 0x17 jne fail
        0xB8, 0x01, 0x00, 0x00, 0x00,               # 0x19 mov eax,1
        0xC3,                                       # 0x1e ret
        0x31, 0xC0, 0xC3,                           # 0x1f fail: xor eax,eax; ret
    ])
    BASE2 = 0x400000
    ev2 = UnicornEvaluator([(BASE2, code2.ljust(0x1000, b"\x00"))], BASE2, arg_reg="rdi", length=8)
    _acc, tr2 = ev2.run_once(struct.pack("<I", magic2) + struct.pack("<I", ver2))
    fields2 = extract_arg_compares(tr2, "rdi")
    assert (0, magic2) in fields2 and (4, ver2) in fields2, (
        f"engine must skip a call and recover the field after it: {[(o, hex(i)) for o, i in fields2]}")

    # A DOUBLE-FETCH validator — the example validator ROOT shape: it reads the SAME field twice and
    # compares it against two DIFFERENT constants (check-then-commit). No static buffer
    # satisfies both; the tool must FLAG this as a race, not send the model chasing a
    # preimage. (Constants here are arbitrary — never the box's real values.)
    ma, mb = 0x11111111, 0x22222222
    code3 = bytes([
        0x8B, 0x07,                            # 0x00 mov eax,[rdi]   (first read)
        0x3D, *struct.pack("<I", ma),          # 0x02 cmp eax, MODE_A
        0x8B, 0x07,                            # 0x07 mov eax,[rdi]   (re-read)
        0x3D, *struct.pack("<I", mb),          # 0x09 cmp eax, MODE_B
        0xB8, 0x01, 0x00, 0x00, 0x00,          # 0x0e mov eax,1
        0xC3,                                  # 0x13 ret
    ])
    ev3 = UnicornEvaluator([(0x400000, code3.ljust(0x1000, b"\x00"))], 0x400000,
                           arg_reg="rdi", length=8)
    _a3, tr3 = ev3.run_once(b"\x00" * 8)
    df = detect_double_fetch(extract_arg_compares(tr3, "rdi"))
    assert df and df[0][0] == 0 and set(df[0][1]) == {ma, mb}, (
        f"double-fetch race must be detected at +0: {df}")
    assert race_diagnosis(df) and "race-condition-toctou" in race_diagnosis(df)


def _int(v: str) -> int:
    return int(v, 0)


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="python3 -m harness.re_emulate",
        description="Emulate one validator function and read the frame it demands "
                    "(offsets + required constants). See the protocol-reversing skill.")
    p.add_argument("binary", nargs="?", help="ELF containing the validator")
    p.add_argument("--start", type=_int, help="validator start vaddr (from r2/objdump)")
    p.add_argument("--end", type=_int, default=0, help="stop vaddr (default: run to ret)")
    p.add_argument("--len", type=int, default=16, dest="length", help="candidate frame length")
    p.add_argument("--arg", default=None, help="register holding the frame pointer (default rdi)")
    p.add_argument("--base", type=_int, default=None, help="load base (default: 0, or a PIE base)")
    p.add_argument("--arch", default="x86-64", choices=sorted(_ARCH),
                   help="foreign arch: run the binary under qemu-<arch>-static instead")
    p.add_argument("--accept", type=_int, default=None,
                   help="RAX value that means 'accepted' (default: any non-zero)")
    p.add_argument("--seed", default=None, help="hex bytes of the starting frame")
    p.add_argument("--diff", action="store_true", help="also byte-flip to find gating offsets")
    p.add_argument("--solve", action="store_true",
                   help="construct an accepting input by constraint propagation over the "
                        "validator's field checks (magic/version/command/computed dwords). "
                        "Prints the frame hex; for a staged validator this IS the answer")
    p.add_argument("--no-skip-calls", action="store_true",
                   help="execute call instructions instead of skipping them (default: skip, so "
                        "a validator that calls helpers / clock_gettime still emulates)")
    p.add_argument("--call-ret", type=_int, default=0,
                   help="value a skipped call 'returns' in RAX (default 0); flip to 1 to explore "
                        "the branch a helper's return gates")
    p.add_argument("--selftest", action="store_true", help="prove the emulation path in-image")
    args = p.parse_args(argv)

    if args.selftest:
        selftest()
        print("re_emulate selftest: OK")
        return 0
    if not args.binary or args.start is None:
        p.error("BINARY and --start are required (or use --selftest)")

    seed = bytes.fromhex(args.seed) if args.seed else None
    skip_calls = not args.no_skip_calls
    accepted, fields, trace = emulate(
        args.binary, args.start, args.end, length=args.length, arch=args.arch,
        arg_reg=args.arg, base=args.base, accept=args.accept, seed=seed,
        skip_calls=skip_calls, call_ret=args.call_ret)
    print(f"accepted: {accepted}  (emulated {len(trace)} instructions)")
    if fields:
        print("frame fields the validator compares (offset -> required value):")
        for off, imm in fields:
            print(f"  [+{off:#04x}]  == {imm:#x}")
        cold_race = race_diagnosis(detect_double_fetch(fields))
        if cold_race:
            print(cold_race)
    elif len(trace) <= 1:
        print("emulation made no progress (faulted at --start): check --start is the function "
              "entry vaddr and --base matches the load base; for a PIE pass the file offset "
              "and let the tool add the base.")
    else:
        print("no direct arg-compares found — widen --start/--end or try --diff, and "
              "confirm --arg is the frame-pointer register.")
    if args.diff or args.solve:
        data = open(args.binary, "rb").read()
        base = args.base if args.base is not None else (0x555555554000 if elf_is_pie(data) else 0)
        maps = plan_mappings(data, parse_load_segments(data), base=base)
        s = args.start + (base if elf_is_pie(data) else 0)
        e = (args.end + base) if (args.end and elf_is_pie(data)) else args.end
        ev = UnicornEvaluator(maps, s, e, arch=args.arch, arg_reg=args.arg, length=args.length,
                              accept=args.accept, skip_calls=skip_calls, call_ret=args.call_ret)
        if args.diff:
            rep = differential(ev, args.length, seed=seed)
            print(f"gating offsets (byte-flip): {rep.gating_offsets()}")
        if args.solve:
            def _oracle(buf: bytes):
                accepted, trace = ev.run_once(buf)
                return accepted, extract_arg_compares(trace, ev.arg_reg)
            frame, ok = solve(_oracle, args.length, seed=seed)
            if ok:
                print("solve: ACCEPTED")
                print(f"  frame ({args.length} bytes): {frame.hex()}")
            else:
                # Before blaming a whole-buffer hash, check for a double-fetch race — the
                # accept may be un-constructible because the validator wants one field to be
                # two different values (check-then-commit), which a STATIC solve can never do.
                race = race_diagnosis(probe_double_fetch(_oracle, args.length, seed=seed))
                if race:
                    print(f"solve: {race}")
                    print(f"  frame ({args.length} bytes): {frame.hex()}  (fixed fields only)")
                else:
                    print("solve: not field-solvable (accept gated by more than field checks "
                          "— e.g. a whole-buffer hash; the fixed fields it could set are written)")
                    print(f"  frame ({args.length} bytes): {frame.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

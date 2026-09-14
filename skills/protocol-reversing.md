---
name: protocol-reversing
when: a service speaks a custom binary/text protocol (opcode/length/checksum framing, TLV, a bespoke cJSON wire format) you must reverse before exploiting
tools: [python_exec, session, shell]
phase: exploit
---
# Reversing a custom wire protocol

You usually have the client/server binary — reverse the framing, then script it. The
binary is GROUND TRUTH. Any spec you found in a config/README/notes is only a hint and
may be a planted decoy — `consult_skill 'deception-awareness'` and reconcile it against
the binary before spending budget (see "Trust the binary, not the notes" below).

1. Triage the binary: `file ./bin; checksec ./bin`. If it's firmware or an opaque
   blob, `binwalk ./bin` (and `binwalk -e ./bin` to extract embedded filesystems).
2. Find the parser: open in radare2 (`r2 -A ./bin`; `afl`, then `pdf @ sym.handle`) or
   `objdump -d -M intel ./bin`. If radare2's r2dec plugin is present, `pdd @ sym.handle`
   gives readable pseudo-C — far easier than raw disasm on an obfuscated handler. Look
   for the read loop and how it splits the buffer — that reveals the frame: a
   magic/opcode, a length field (endianness!), a payload, a trailing checksum/XOR, and
   the exact constants each field is compared against.

   **Before you hand-read it, ask: is the parser OBFUSCATED?** If so, do NOT read the
   control flow to guess the frame — jump straight to emulation (§ below). Tells:
   - **Control-flow flattening**: one big dispatch loop driven by a state variable that
     is reassigned to large magic constants (`state = 0xDEADBEEF; ... switch(state)`),
     often a `state % N` index into a jump table. Those flattener constants are
     DISPATCHER STATE, not your protocol's magic/opcode/version. Hand-reading them as
     command IDs is the classic trap — it burns the whole run fuzzing values the wire
     never uses.
   - **Opaque predicates** (`if (x*x - x ...)` always-true junk), computed/XOR'd magic,
     constants that arithmetic never derives from your input bytes.

   Diagnostic from the wire side: **if every opcode/command you send gets the same error
   back, your FRAME MODEL is wrong** — you are being rejected at a front gate (magic /
   version / length) before the command is ever inspected. Stop enumerating the opcode
   space; emulate the validator to learn what the FIRST bytes must be.
3. Model the frame in pwntools and prove it against a local copy first:

   ```python
   import struct
   def frame(op, payload):
       body = bytes([op]) + struct.pack('<H', len(payload)) + payload
       chk = 0
       for b in body: chk ^= b        # match the binary's exact checksum
       return body + bytes([chk])
   io = process('./bin')              # local first
   io.send(frame(0x01, b'{"k":"v"}')) # then io = remote(host, port)
   print(io.recvall(timeout=2))
   ```

4. Confirm you can round-trip a benign message, THEN drive the bug (overflow / heap /
   logic) through the frame. Wrap connect+attack in a reconnect-and-retry loop —
   networked pwn targets drop connections; retry rather than give up.
5. If a reference client and a packet sniffer are available (`tcpdump`/`tshark` — check
   `command -v` first, not guaranteed baked), capture real frames to a pcap and replay
   them with your `frame`. Otherwise derive the frame purely from the binary (step 2) —
   that always works offline.

## Obfuscated parser → EMULATE the validator (first move, not a fallback)

An obfuscated parser (control-flow flattening, opaque-predicate jump table, computed
constants, XOR'd magic) defeats static reading: you mis-slice the real constants and
waste the run on wrong values. The fix is to run just that one function and watch it.

- **Fastest — the baked helper does the emulation for you.** Don't hand-roll unicorn
  under a clock. Find the validator's address range in radare2/objdump (`afl`, then the
  handler's start/end), then:

  ```bash
  # reads out each input offset the validator compares and the constant it demands
  python3 -m harness.re_emulate ./bin --start 0x1189 --end 0x1240 --len 32
  #   accepted: False
  #   frame fields the validator compares (offset -> required value):
  #     [+0x00]  == 0x...        <- magic
  #     [+0x04]  == 0x...        <- version
  #     [+0x06]  == 0x...        <- command word
  python3 -m harness.re_emulate ./bin --start 0x1189 --len 32 --diff   # byte-flip: which offsets gate
  python3 -m harness.re_emulate --selftest                              # prove the engine works here
  ```

  It maps the PT_LOADs correctly (PIE handled), runs the function on a candidate frame,
  and attributes every `cmp` against the argument buffer to an input offset — so the
  magic/version/command fall out directly instead of being guessed from flattener junk.
  `--arg` sets the frame-pointer register (default `rdi`); `--accept 0x1` if a specific
  RAX means "accepted"; foreign arch → run the binary under `qemu-<arch>-static`.

  **It handles REAL (non-flat) validators, not just self-contained ones.** It runs INTERNAL
  helper calls (a call whose target is inside the binary — e.g. a measurement's hash/state
  functions) and SKIPS only EXTERNAL calls whose target is unmapped (a PLT stub, `clock_gettime`,
  `strtoul`) — so the real logic executes while syscalls that would fault are stubbed. It also
  auto-maps stray data reads (globals/stack). So point it at the actual dispatcher/validator
  even if it calls out — including a **measurement loop** (`fn -> hash + state-machine`): the
  helpers run, the timing syscall is stubbed, and you get a true accept/reject over a candidate
  buffer. BUT a measurement loop that **re-reads your buffer each iteration** is a race window, not
  content to forge — if a field is compared against two different constants (or read repeatedly in
  the loop), `--solve` flags `RACE` and you must flip it concurrently, not construct it (see
  `--solve` below and `consult_skill 'race-condition-toctou'`). Levers: `--call-ret 1` changes
  what a skipped external call "returns" (run both ways
  and diff); `--no-skip-calls` executes everything. "emulation made no progress (faulted at
  --start)" = wrong `--start`/`--base` (for a PIE pass the FILE OFFSET, let the tool add base).

  **`--solve` constructs an accepting input for you.** It propagates the validator's own field
  checks (magic/version/command/computed dwords) into a buffer until it accepts, and prints the
  frame hex — the answer for a staged frame validator, and it sets the fixed prefix (e.g. a file
  magic) for a measurement file. Two ways it reports "no static answer" — they need OPPOSITE
  responses, so READ WHICH ONE it prints:
  - **`RACE (double-fetch / TOCTOU)`** — it found ONE field compared against TWO different
    constants (the validator re-reads it and demands different values, e.g. a `PREVIEW` then a
    `COMMIT` mode). NOT constructible and NOT a hash — it is a **race**. Do NOT build a file;
    flip that field concurrently while resubmitting. `consult_skill 'race-condition-toctou'`.
    Emulation is single-threaded over static memory, so it can never *win* this for you — only
    tell you it is a race. Point `--start` at the DECISION function (the one that reads the field
    and branches / does the measurement), not just an inner helper, so BOTH reads land on one
    trace and the race is detected; set `--arg` if the buffer pointer is not in `rdi`.
  - **`not field-solvable`** (no race reported) — the accept really is gated by more than field
    compares (a whole-buffer hash): emulate the hash function itself over your candidate bytes (it
    now runs, since internal calls execute), then search/construct the remaining bytes against it.

  If it runs but finds no fields, widen `--start/--end`, check `--arg`, or `--diff`.
- **Roll it by hand with unicorn** when you need to customise (odd calling convention,
  set up global state first, decrypt in place). No ptrace, no running the
  whole service — map its code, feed a candidate frame in memory, run just that function,
  and read what it compares against / whether it returns "accepted". You can do this on
  the binary you EXFILTRATED — **no daemon, no group, no file delivery to set up.** This
  is the intended shortcut for an opaque validator and it sidesteps every local-rig time
  sink.

  ```python
  from unicorn import *
  from unicorn.x86_const import *
  from pwn import ELF
  elf = ELF('./bin')
  data = open('./bin', 'rb').read()
  BASE = elf.address or 0x400000     # non-PIE load base (readelf -l); PIE -> pick one
  mu = Uc(UC_ARCH_X86, UC_MODE_64)
  # approximation: map the whole file at BASE (fine when the first PT_LOAD at offset 0
  # covers .text, the common non-PIE case). For precision map each PT_LOAD at its p_vaddr.
  mu.mem_map(BASE, 0x400000); mu.mem_write(BASE, data)
  STACK = 0x900000; mu.mem_map(STACK, 0x100000)
  mu.reg_write(UC_X86_REG_RSP, STACK + 0x80000)
  FRAME = 0xb00000; mu.mem_map(FRAME, 0x1000)
  mu.mem_write(FRAME, bytes(16))                 # your candidate frame bytes
  mu.reg_write(UC_X86_REG_RDI, FRAME)            # SysV arg0 = pointer to the frame
  # log every compare so the real magic/opcode/version falls out of the immediates:
  def trace(uc, addr, size, _):
      code = uc.mem_read(addr, size)
      if code and code[0] in (0x3d, 0x81, 0x83):  # cmp eax,imm / cmp r/m,imm
          log.info('cmp @ %#x: %s', addr, code.hex())
  mu.hook_add(UC_HOOK_CODE, trace)
  mu.emu_start(BASE + validate_off, BASE + validate_end)   # offsets from radare2/objdump
  print('accepted?' , hex(mu.reg_read(UC_X86_REG_RAX)))    # return value
  ```

  The immediates the trace prints are a MIX of real compare targets (what your input must
  equal) and flattener junk (dispatcher state that never touches your bytes). Don't sort
  them by eye. **Flip ONE input byte at a time, re-emulate, and keep only the constants
  whose comparison flips the result reject→accept** — those are the real frame fields
  (magic at off0, version at off4, command word at off6, …); the rest is noise. Foreign
  arch? swap `UC_ARCH_*`/`UC_MODE_*` and the `*_const` import.
- **Attach to the live service with gdb** if ptrace is available — but this is the SECOND
  choice; it needs a running daemon. PROBE FIRST: `strace /bin/true` (or
  `gdb -batch -ex run /bin/true`). If it errors (EPERM / a seccomp-sealed cell drops
  CAP_SYS_PTRACE), gdb/strace/ltrace are dead here — use the unicorn emulation above. If
  ptrace works and you must observe the REAL process, stand the daemon up FAST: create any
  group/user its startup demands (`groupadd <grp>`, `useradd <u>`), place the files it
  reads at the expected paths readable by the uid it runs as (`chmod`/`chown`) — but if
  setup fights back (a permission battle, a missing dependency), drop it and emulate the
  validator instead. Emulation needs none of this.

## Unix-domain socket services (SO_PEERCRED auth, SCM_RIGHTS fd-passing)

A root-owned control socket often gates on the CLIENT'S credentials and passes file
descriptors, not just bytes — reversing the frame is not enough, you must satisfy the
ancillary channel:
- **SO_PEERCRED**: the daemon reads your peer uid/gid/pid via
  `getsockopt(SOL_SOCKET, SO_PEERCRED)`. You cannot forge it — you must actually be the
  expected uid/group (become that user first via your foothold), then connect.
- **SCM_RIGHTS**: the daemon expects you to PASS an open fd over the socket (e.g. a
  diagnostic/artifact fd it validates, or it hands YOU back an fd wired to a privileged
  process's stdio) via `sendmsg`/`recvmsg` ancillary data. Reverse WHICH fd it validates
  or returns and how, then send/receive it.

The exact `getsockopt`/`sendmsg`/`recvmsg` code — reading SO_PEERCRED, sending fds with
SCM_RIGHTS, `MSG_CMSG_CLOEXEC` on receive — is in `pwntools-recipes` ("Unix-domain
sockets"). Reverse the frame here; send it with those primitives.

## Trust the binary, not the notes (decoy discipline)

If you found a `DEV_NOTES.md`/`.ini`/`.config` describing the protocol (a magic, a
port, a command id, a version), do NOT transcribe it into your `frame()`. RECONCILE it
against the binary's parser first: a value the parser never reads is a decoy pointing at
a removed feature, and it will eat the whole run. Record the real constants with
`record_finding(status='confirmed', ...)` and each disproven documented value with
`mark_dead('<value> = decoy — binary says otherwise')` so you never re-test it. Full
discipline in `deception-awareness`.

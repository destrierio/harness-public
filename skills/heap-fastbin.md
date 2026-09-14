---
name: heap-fastbin
when: heap bug on older glibc, or fastbin-sized chunks; fastbin dup
tools: [python_exec]
phase: exploit
---
# fastbin dup / attack

Fastbins: per-size LIFO for small chunks (<=0x80 default). Only check: `chunk->size` at the head must
match the bin's size class (fastbin dup into arbitrary requires a fake size field).

fastbin dup:
```python
free(0); free(1); free(0)            # double-free 0 with 1 between it (avoids the "double free" adjacency check)
alloc(2, sz, p64(target - 0x10))     # fd of chunk0 -> fake chunk near target (target-0x10 so size lines up)
alloc(3, sz, b'A'); alloc(4, sz, b'A')
victim = alloc(5, sz, payload)       # lands on target
```
The 0x10 offset accounts for the chunk header; the 8 bytes at `target+8` (the fake size) must be a valid
fastbin size (e.g. corrupt `__malloc_hook-0x23` so the misaligned 0x7f acts as size for a 0x70 chunk).
Classic target pre-2.34: `__malloc_hook` / `__free_hook` -> one_gadget. See `libc-id-and-leak`.
Consolidate to unsorted bin for a libc leak: alloc a large chunk, free it, read its fd/bk (main_arena).

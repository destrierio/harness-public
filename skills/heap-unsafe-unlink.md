---
name: heap-unsafe-unlink
when: heap overflow into an in-use chunk's header, glibc with unlink macro
tools: [python_exec]
phase: exploit
---
# unsafe unlink

Turn a heap overflow into a near-arbitrary write by faking a free chunk so that `unlink()` during
consolidation writes a pointer you control. Modern glibc enforces `FD->bk == P && BK->fd == P` and
size sanity, so you craft a fake chunk INSIDE a controlled buffer at known address `P` (a global that
holds the heap pointer, e.g. a chunk-pointer array):

```python
fd = P - 0x18
bk = P - 0x10
fake = flat(0, 0, fd, bk)            # prev_size, size, fd, bk satisfy FD->bk==P, BK->fd==P
# overflow the next chunk's header: prev_size = size_of_fake, size &= ~PREV_INUSE
# free the next chunk -> unlink(fake) -> P now points to P-0x18
```
After unlink, the pointer array entry aliases itself; edit it to point at a GOT entry / __free_hook,
then overwrite that with system/one_gadget. Requires a writable global holding the chunk pointer.
Prefer tcache/fastbin techniques when available; unsafe-unlink is for when those are blocked.

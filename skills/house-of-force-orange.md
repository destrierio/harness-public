---
name: house-of-force-orange
when: advanced heap - top chunk overwrite (force) or FSOP via _IO (orange/apple)
tools: [python_exec]
phase: exploit
---
# House of Force / Orange / Apple (advanced heap)

House of Force (pre-2.29; top-chunk size overwritable): overwrite the top chunk `size` with -1
(0xffff...ff), then `malloc(target - top - 0x20)` to move the top to an arbitrary address, then a final
malloc returns it. Dead on 2.29+ (top size is sanity-checked).

House of Orange (no free() available): overflow the top chunk size to a small value so the next large
malloc frees the old top into the unsorted bin; then corrupt `_IO_list_all` via unsorted-bin attack and
forge an `_IO_FILE` (`_IO_2_1_stdout_`) whose vtable points at your `system`. Triggers on abort/exit.

House of Apple 2 (glibc 2.34+, hooks removed): forge `_IO_FILE` with `_IO_wfile_jumps` /
`_wide_data->_wide_vtable` so `_IO_flush_all` (on exit) calls a controlled pointer with a controlled
`this` -> RCE. This is the go-to when `__free_hook`/`__malloc_hook` are gone.

These are last-resort; confirm the exact glibc first (`libc-id-and-leak`) and read a current write-up for
the offset details of that version. Prove each primitive in `python_exec` locally before remote.

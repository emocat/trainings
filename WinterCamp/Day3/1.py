from pwn import *


context.log_level="debug"

r=remote("pwn.sixstars.team",22501)
r.recvline()
for i in range(16):
    b=r.recvuntil("(")
    a=r.recvuntil(")")
    a=a[:-1]
    a=int(a,16)
    if a<=0x18:
        a=33
    else:
        a=a+8
        b=a%16
        if b!=0:
            a=a/16*16+17
        else:
            a=a/16*16+1
    print a
    r.sendline(str(a))

r.interactive()

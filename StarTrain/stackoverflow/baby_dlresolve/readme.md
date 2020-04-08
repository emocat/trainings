# Baby_dl_resolve
## Process
1. modify fake [.rel.plt] - r_offset + r_info       [0x8]
2. modify fake [.dynsym] - st_name + ...            [0x10]
3. modify fake [.dynstr] - "system"                 [0x8]
4. read fake data to bss chunk.
5. return to [plt+11] with rel_offset pushed in stack, and call system("/bin/sh") to get shell.

## Structure
|0x0|0x4|0x8|0xc|
|:-:|:-:|:-:|:-:|
|r_offset|r_info|0|st_name|
|st_value|st_size|st_others|"syst"|
|"em\x00\x00"|"/bin"|"/sh\x00"|0|

|0x0|0x4|0x8|0xc|
|:-:|:-:|:-:|:-:|
|fake_rel|fake_rel|0|fake_sym|
|fake_sym|fake_sym|fake_sym|fake_str|
|fake_str|binsh|binsh|0|

## Warnings
1. Mind the offsets of plt[6] (*0x8), r_info (>>8,\*0x10), st_name(\*0x1)
2. Be careful offset between fake_sym and sym[0] should be 16n.
3. payload should be ret + rel_off + new_ret + [parameters, ...]

## Easy Solution
python getoffset.py ./pwn
python dl-resolve-i386.py ./pwn 44

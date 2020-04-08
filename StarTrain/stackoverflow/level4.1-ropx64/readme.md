ROP链有些限制，所以要按照一定的顺序来pop。

因为syscall之后的rcx会被改成下一条指令的地址，通过这个缺口来成功构造ROP链

然后write控rax，调用mprotect，read，执行shellcode即可。

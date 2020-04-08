很有意思的一道格式化字符串的题，只能printf一次。

具体思路是同时修改_fini_array为main，got['strlen']为plt['system']，8位数字太大了的话，可以4位两次写入，最后引发system("/bin/sh")。

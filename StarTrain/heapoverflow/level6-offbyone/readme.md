add和edit可以溢出到下以堆块的大小字节。

可以构造三个堆，通过第一个堆修改第二个堆的大小，将第二个堆改大，free第二个堆，然后连续malloc两次，就可以得到两个指向第三个堆的指针，就可以double-free或者uaf了。

最后改完\_\_malloc\_hook之后，使用Pool的指针连续free一个堆块两次来get shell。

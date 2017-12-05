# 漏洞点
&#8195;这里我认为的漏洞点有两个，一个是createfile时的strcpy，另一个是editfile时的memcpy，这两个点都可以造成缓冲区溢出
&#8195;strcpy主要是因为read函数不会自动在输入字符串末尾加‘\0’，且strcpy的源是bss段的缓冲区，第一次输入0x200字节的数据，第二字输入0x20字节的数据，最终strcpy的效果都是一样的
&#8195;memcpy主要是size字段设置不正确

# get到的知识点
&#8195;1、学习了堆的结构，在单步调试的过程中，观察到Fastbin的FIFO和unsortbin的FILO，直观的了解到为啥要通过两次free来泄露堆地址，以及怎么计算heap_base，不过在这里好像泄露堆基址用不上
&#8195;2、了解了unlink机制，fakechunck的构造，以及怎么绕过unlink的检测

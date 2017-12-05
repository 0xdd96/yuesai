# 漏洞点
&#8195;这里我认为的漏洞点有两个，一个是createfile时的strcpy，另一个是editfile时的memcpy，这两个点都可以造成缓冲区溢出<br>
&#8195;strcpy主要是因为read函数不会自动在输入字符串末尾加‘\0’，且strcpy的源是bss段的缓冲区，第一次输入0x200字节的数据，第二字输入0x20字节的数据，最终strcpy的效果都是一样的<br>
&#8195;memcpy主要是size字段设置不正确<br>

# get到的知识点
&#8195;1、学习了堆的结构，在单步调试的过程中，观察到Fastbin的FIFO和unsortbin的FILO，直观的了解到为啥要通过两次free来泄露堆地址，以及怎么计算heap_base，不过在这里好像泄露堆基址用不上<br>
&#8195;2、了解了unlink机制，fake chunk的构造，以及怎么绕过unlink的检测<br>

# 错误记录
&#8195;1、小端存储，也就是为什么要改size送的是payload = '7' * 0xf8 + p64(0x110)[:2] + '\x00'<br>
&#8195;2、一开始以为create_file('file7', 0x28, 'x' * 0x7 + '\x00')这步是多余的，后来发现是为了创造两个连续的堆块<br>
&#8195;3、当修改了file8的content堆块的flag字段之后，认为file7的content堆块已经是free状态，此时再次执行free操作就会报错，因此在构造fake chunk时可以通过edit操作<br>


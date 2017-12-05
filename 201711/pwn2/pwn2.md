# 漏洞点
&#8195;这里我认为的漏洞点有两个，一个是createfile时的strcpy，另一个是editfile时的memcpy，这两个点都可以造成缓冲区溢出
&#8195;strcpy主要是因为read函数不会自动在输入字符串末尾加‘\0’，且strcpy的源是bss段的缓冲区，第一次输入0x200字节的数据，第二字输入0x20字节的数据，最终strcpy的效果都是一样的
&#8195;memcpy主要是size字段设置不正确


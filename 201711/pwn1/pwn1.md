# 漏洞点
<br>
&#8195;整数溢出，如下所示，可以进行下溢<br>

```
__isoc99_scanf("%d", &v1);
    if ( v1 > 3 )
```

# 利用
<br>
&#8195;首先通过遍历找到能到下溢到EIP的index，然后构造rop链<br>
  
# 错误记录
&#8195;在传送数据时，使用0xffffffff来表示-1，结果传入程序中变成了0x7fffffff，通过查询，得到如下解释<br>

```
> If passing it "FFFFFFFF" returns 0x7FFFFFFF then it's working 
> perfectly. That's a positive hexadecimal number and it's too big to fit 
> in a signed long, so it returns a positive overflow (LONG_MAX).
```
&#8195;在老干部的帮助下，得到的理解时，python在处理时会把0xffffffff当成一个大整数，当它发现这数超过了LONG_MAX时，就会将其设置为LONG_MAX，即0x7fffffff

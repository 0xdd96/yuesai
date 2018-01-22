很难受，有个知识点，还没有去看printf的源码，有时间一定去看一看。利用的还是malloc_hook的机制。不过对malloc_hook不是很了解，后续还要再学习啊！
```
printf打印出足够多字节时（大于65536）会调用malloc，malloc的字节数为needed + 0x20
```
这个题目还有一点，got表不可覆盖，利用的是程序初始化时会执行.init_array节里的函数，exit时会执行.fini_array节里的函数来实现

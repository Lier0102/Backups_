#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF("./prob")
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "host3.dreamhack.games 8296".split()


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
    p = remote(HOST, PORT)
    libc = ELF("./lib-mips/libc.so.6")  # or other exact path
elif args.DOCKER:
    p = remote("localhost", 9001)
else:
    p = process(env={"LD_PRELOAD": "./lib-mips/libc.so.6"})  # or env can be added
    libc = ELF("./lib-mips/libc.so.6")


p.interactive()

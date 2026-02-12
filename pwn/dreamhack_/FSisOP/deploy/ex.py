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

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6') # or other exact path
else:
    p = process() # or env can be added
    libc = e.libc

def somefunc():
    pass

# some actions..

p.interactive()
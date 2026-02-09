from pwn import *

context.binary = elf = ELF('./nullnull')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "ASDF 1234".split()

if args.REMOTE:
    p = remote(HOST, PORT)
    libc = ELF('./libc.so.6') # or other exact path
else:
    p = process() # or env can be added
    libc = e.libc

def somefunc():
    pass

# some actions..

p.interactive()
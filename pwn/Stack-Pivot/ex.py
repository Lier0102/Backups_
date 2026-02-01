from pwn import *

context.binary = e = ELF('./vuln')

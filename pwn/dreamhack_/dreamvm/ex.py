from pwn import *

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

e = ELF('./dreamvm')
HOST, PORT = "host8.dreamhack.games 1234".split()

'''
메인 아이디어
> read, write를 할 수 있다?
-> write_all로 릭하기
-> read로는 릭하기 위한 준비...
'''

'''
디컴파일된 결과로 분석

case 1:
    v16 -=8
    *v16 = v17[0]

case 2:
    v17[0] = *v16
    v16 += 8

case 3:
    v17[0] += *v9+1; rip(??맞나) += 9

case 4:
    v16 += *v9+1; rip += 9

case 5:
    write_all() < 읽어서 8바이트 출력

case 6:
    read_all()
'''

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process('./dreamvm')



# gdb.attach(p)
# pause()

p.interactive()
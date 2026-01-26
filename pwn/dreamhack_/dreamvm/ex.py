from pwn import *
import struct

context(arch="amd64", bits=64, endian="little")

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
    v17[0] += *v9+1; rip(??맞나) += 9(뒤로 8개의 값(바이트)들을 받아 누산기에 더함)

case 4:
    v16 += *v9+1; rip += 9(얘는 3번이랑 같은데 스택 포인터에 더함)

case 5:
    write_all() < 읽어서 8바이트 출력

case 6:
    read_all()
'''

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = process('./dreamvm')


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
-) vm 문제를 풀어본 적이 단 한 번도 없음.

2. 머신에 넣을 코드를 어떻게 입력해야할지 감도 안 잡힘. AI를 쓰려고 했으나, 고작 4레벨 vm 문제에 볼 게 뭐가 있나 싶어 고집 부리다 풀이 봄.
- ) (쨍그랑!!!)

... 적절한 변명도 없지만 굳이 모아서 말하자면 그렇습니다..
그냥 경험도 부족한데 너무 오만했던 것 같음
1월도 얼마 남지 않았으니 지금이라도 귀찮았던 걸 해야할듯
'''

CodeSize = 0x100

##
PUSH = b'\x01'
POP = b'\x02'

ADD_AC = b'\x03'
ADD_SP = b'\x04'

OUT = b'\x05'
IN = b'\x06'

if __name__ == '__main__':
    e = ELF('./dreamvm')
    

p.interactive()
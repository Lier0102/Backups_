from pwn import *

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

'''
  puts("1. create/update an animal");
  puts("2. walk with the animal");
  puts("3. rename the animal");
  puts("4. quit");
'''

## 분석
'''
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
'''

# main의 프레임 크기: 0x32
# v4가 메뉴 선택지 저장용. (rbp-2c)
# v5[16]이 버퍼. (rbp-0x28)
# sfp
# ret

# 기능 요약

# 1. 동물 정보 생성 / 수정
# 2. 동물과 산책
# 3. 동물 이름 변경 -> 아마 임의 주소 쓰기로 사용할 수 있을듯
# 4. 종료

# a1 = 동물 구조체 느낌
# *a1 = 동물 타입
# a1+8 = 이름 버퍼
# a1+24(도마뱀, 햄스터), a1+40(개, 고양이) = 이름 크기 버퍼
# (BYTE)a1+32, (WORD)a1+48 = 기본 프로필(?) 저장 위치

# 레이스 컨디션으로 type confusion 유발 가능, size 조작해서 원하는 만큼 쓰는 거 가능할듯.
# printf가 %s로 출력할 때, 꽉 차 있으면(null 없으면) 쭉 나오니까 이걸로 leak 가능
# 얘를 바탕으로 입력 가능한 버퍼와의 거리 구하거나, pie_base leak 하거나, libc_leak 할 수 있어 보임
# GOT overwrite는 불가, 바이너리에는 쓸만한 ROP gadget 없음.
# mprotect ROP, one_gadget, 아니면 ROP 쓰는게 정배로 보임


p.interactive()
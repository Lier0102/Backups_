'''
checksec 결과
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

seccomp-tools dump 결과
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0008
 0006: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL

x86-64 아키텍쳐에서 환경 구성 후 실행, 0x40... 대충 x32 ABI 사용
execve, execveat 사용 불가로 system, execve 막힘
이런 경우 orw 사용, 근데 딱히 할 방법이..?

간단히 5개의 이미 등록된 도시를 여행하게 해주는 프로그램이다.
경로에 대해
추가/삭제/조회/수정/다른 도시와의 거리 계산
을 수행할 수 있다.

1. Add route를 동적으로 분석해보면
이동수단을 선택하고
출발지/도착지를 입력한 뒤,
거리를 입력하고 노트를 남길 수 있다. << 그냥 저장용인듯

거리가 비상식적으로 먼 경우 입력을 취소하고 다시 메뉴로 간다.


2. Delete route
원하는 출발지/목적지를 입력하면 이미 추가된 적이 있는 경우 경로를 제거할 수 있다.

3. Show route
출발지/도착지를 입력하면 해당하는 경로의 정보를 보여준다.
정보에는 거리/노트가 있다.
없으면 안 보여줌;;

4. Edit route
수정 못한다며 프로그램 강종함;;

5. Calculate the distance
광저우를 기준으로 거리를 계산해 보여줌.
처음, 아무런 경로를 입력하지 않은 상태에서 광저우를 제외한 모든 곳으로부터 거리가
9999km로 표시됨

나머지 IDA로 분석한 내용은 나중을 위해 그대로 올려 놓은..


'''
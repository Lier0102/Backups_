from pwn import *

HOST, PORT = 'host8.dreamhack.games 1234'.split()

'''
분석한 내용:
1. 내가 싫어하는, 그리고 잘 모르는 cpp 코드.
2. 그냥 쉘코드 입력 받아서 실행, 근데 그냥의 기준이 좀 남다름;

-> 모든 레지스터를 초기화, 어찌보면 좋은 것 같기도?
-> 입력받은 쉘코드를 0x56780000에서 실행, (0x12340034 ~ (4044 bytes) < 이게 입력)
-> 입력받은 쉘코드의 각 바이트에 *= 2, 따라서 홀수면 안됨, 짝수 바이트여야함;; 
-> 

pwndbg> x/52bx 0x2080(blow_up)
0x2080 <_ZL7blow_up>:   0x48    0x31    0xc0    0x48    0x89    0xc3    0x48    0x89
0x2088 <_ZL7blow_up+8>: 0xc1    0x48    0x89    0xc2    0x48    0x89    0xc7    0x48
0x2090 <_ZL7blow_up+16>:        0x89    0xc6    0x49    0x89    0xc0    0x49    0x89    0xc1
0x2098 <_ZL7blow_up+24>:        0x49    0x89    0xc2    0x49    0x89    0xc3    0x49    0x89
0x20a0 <_ZL7blow_up+32>:        0xc4    0x49    0x89    0xc5    0x49    0x89    0xc6    0x49
0x20a8 <_ZL7blow_up+40>:        0x89    0xc7    0x48    0xc7    0xc4    0xf8    0x0f    0x78
0x20b0 <_ZL7blow_up+48>:        0x56    0x48    0x89    0xe5

0x2080:  48 31 c0        xor    rax, rax
0x2083:  48 89 c3        mov    rbx, rax
0x2086:  48 89 c1        mov    rcx, rax
0x2089:  48 89 c2        mov    rdx, rax
0x208c:  48 89 c7        mov    rdi, rax
0x208f:  48 89 c6        mov    rsi, rax
0x2092:  49 89 c0        mov    r8, rax
0x2095:  49 89 c1        mov    r9, rax
0x2098:  49 89 c2        mov    r10, rax
0x209b:  49 89 c3        mov    r11, rax
0x209e:  49 89 c4        mov    r12, rax
0x20a1:  49 89 c5        mov    r13, rax
0x20a4:  49 89 c6        mov    r14, rax
0x20a7:  49 89 c7        mov    r15, rax
0x20aa:  48 c7 c4 f8 0f 78 56    mov rsp, 0x56780ff8
0x20b1:  48 89 e5        mov    rbp, rsp


'''

if args.REMOTE:
    p = remote(HOST, PORT)
else:
    p = proces('./chal')

shellcode = r'''

'''

p.interactive()

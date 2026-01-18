# test_simple.py
from pwn import *

context.arch = 'amd64'

# 간단한 테스트: push rax (0x50)
# doshl 전: 0x28 (40)
# doshl 후: 0x50 (80) - push rax

payload = b'\x28' * 10  # doshl 후 0x50 * 10이 됨
payload = payload.ljust(0xfcc, b'\x00')

with open('payload.bin', 'wb') as f:
    f.write(payload)

print("payload.bin 생성 완료")
print(f"첫 10바이트: {payload[:10].hex()}")
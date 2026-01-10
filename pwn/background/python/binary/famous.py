import struct
# well-known module.
# 포너블에서도 쓰였음.
# 물론 난 이 메서드 생김새들 때문에 pwntools를 더 좋아하는데..
# 실력 안 좋아서 pwntools에 끌려 다니는 신세..

with open('output', 'rb') as f: # (r)ead as (b)inary
    chunk = f.read(0x10) # read 0x10 bytes
    result = struct.unpack('@dic3x', chunk)
    print(result)
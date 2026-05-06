#!/bin/env python3

quest = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")

known = b"crypto{"

#for c, p in zip(quest, known):
#    print(chr(c ^ p), end="")

# result: myXORke << 그래서 myXORkey로 때려맞추기 시전:

key = b'myXORkey'
res = bytes([c ^ key[i % len(key)] for i, c in enumerate(quest)])
print(res)

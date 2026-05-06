#!/bin/env python3

def xor(a, b):
    res = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
    return res.to_bytes(max(len(a), len(b)), "big")


key1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
key2 = bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e")
key3 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
flag = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")

key2 = xor(key2, key1)
key3 = xor(key3, key2)
flag = xor(flag, key3); flag = xor(flag, key2); flag = xor(flag, key1);

print(flag)

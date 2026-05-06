#!/bin/env python3

quest = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

for key in range(0, 255, 1):
    res = bytes([x ^ key for x in quest])

    try:
        out = res.decode('ascii')
    except:
        continue

    if b"crypto" in res:
        print(f"key = {key}: {res}")

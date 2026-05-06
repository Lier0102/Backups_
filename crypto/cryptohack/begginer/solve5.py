#!/bin/env python3

from pwn import *

quest = "label"
q2 = 13
res = ""

for i in quest:
    i = ord(i) ^ q2
    res += chr(i)

print(quest)
print(res)

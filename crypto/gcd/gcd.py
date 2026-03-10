#!/usr/bin/env python3

def gcd(a, b):
    if (b == 0):
        return a

    return gcd(b, a % b)

a, b = map(int, input().split())
print("gcd(a, b):", end=' ')

tmp = 0
if a > b:
    tmp = a
    a = b
    b = a

print(gcd(a, b))

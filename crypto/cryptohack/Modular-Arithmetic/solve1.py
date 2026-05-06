#!/bin/env python3

def gcd(a, b):
    if a < b:
        a,  b = b, a
    if b == 0:
        return a
    else:
        return gcd(b, a%b)

print(gcd(66528, 52920))

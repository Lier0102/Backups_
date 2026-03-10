#!/usr/bin/env python3

# xgcd(a, b)
# gcd(a, b) == gcd(b, a % b)
# => xgcd(b, a  % b)

def xgcd(a, b):
    if b == 0:
        return a, 1, 0
    
    g, x, y = xgcd(b, a % b) # xgcd(b, r)
    # g = x * b + y * (a % b)

    x = y
    y = (g - a * x) // b

    assert a * x + b * y == g

    return g, x, y

a, b = map(int, input().split())

print('xgcd(a, b):', end=" ")

tmp = 0
if a > b:
    tmp = a
    a = b
    b = tmp

g, x, y = xgcd(a, b)
print(f'{x}x + {y}y = {g}')
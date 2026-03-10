#!/usr/bin/env python3


def gcd(a, b):
    if b == 0:
        return a

    return gcd(b, a % b)


def xgcd(a, b):
    if b == 0:
        return a, 1, 0

    g, x, y = xgcd(b, a % b)  # xgcd(b, r)
    # g = x * b + y * (a % b)

    x = y
    y = (g - a * x) // b

    assert a * x + b * y == g

    return g, x, y


def inverse(a, m):
    g, x, y = xgcd(a, m)

    if g != 1:
        return None

    return x


if __name__ == "__main__":
    a, m = 7, 26
    a_inv = inverse(a, m)

    # a ^ 7 * a_inv ^ 3 ≡ a ^ 4 (mod m)
    assert (a**7 * a_inv**3) % m == (a**4) % m
    assert inverse(8, m) == None

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


def crt(rem, mod):
    a, b = rem
    p, q = mod

    g, alpha, beta = xgcd(p, q)
    assert g == 1

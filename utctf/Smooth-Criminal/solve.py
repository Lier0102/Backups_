#!/usr/bin/env python3

from sympy import factorint
from sympy.ntheory.modular import crt

p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517


def pohlig_hellman_prime_power(g, h, p, q, e):
    """
    Pohlig-Hellman: x mod q^e 를 구한다.

    핵심 아이디어:
      x를 q진법으로 표현하면  x = d_0 + d_1*q + d_2*q^2 + ... + d_(e-1)*q^(e-1)
      각 자리 d_k 를 순서대로 구한 뒤 합산한다.

    각 자리를 구하는 방법:
      gamma = g^((p-1)/q)  →  위수(order)가 정확히 q인 원소
      h_k   = (g^(-x_k) * h)^((p-1)/q^(k+1))
            여기서 x_k = d_0 + d_1*q + ... + d_(k-1)*q^(k-1) (지금까지 구한 부분합)
      그러면 h_k = gamma^(d_k)  가 되므로
      d_k 는 0 ~ q-1 범위에서 brute force 가능 (q 가 작은 소수이므로 빠름)
    """
    order = p - 1
    gamma = pow(g, order // q, p)  # 위수 q 인 원소

    x = 0
    for k in range(e):
        # g^(-x_k) mod p
        g_inv_x = pow(g, (-x) % order, p)
        # h_k = (g^(-x_k) * h)^((p-1) / q^(k+1)) mod p
        h_k = pow(g_inv_x * h % p, order // (q ** (k + 1)), p)

        # gamma^j = h_k 인 j 를 brute force (0 <= j < q)
        d_k = None
        gamma_j = 1
        for j in range(q):
            if gamma_j == h_k:
                d_k = j
                break
            gamma_j = gamma_j * gamma % p

        if d_k is None:
            raise ValueError(f"discrete log not found: q={q}, e={e}, k={k}")

        x += d_k * (q**k)

    return x % (q**e)


def pohlig_hellman(g, h, p):
    """
    Pohlig-Hellman 전체 흐름:
      1. p-1 을 소인수분해
      2. 각 소수 거듭제곱 q^e 에 대해 x mod q^e 를 구함
      3. CRT(중국인의 나머지 정리) 로 전체 x 를 복원
    """
    order = p - 1
    factors = factorint(order)

    print(
        f"[*] p-1 최대 소인수: {max(factors.keys())}  → Smooth! Pohlig-Hellman 적용 가능"
    )
    print(f"[*] 소인수 분해: {factors}\n")

    remainders = []
    moduli = []

    for q, e in factors.items():
        r = pohlig_hellman_prime_power(g, h, p, q, e)
        remainders.append(r)
        moduli.append(q**e)
        print(f"    x ≡ {r:>6}  (mod {q}^{e} = {q**e})")

    print("\n[*] CRT 적용 중...")
    M, x = crt(moduli, remainders)
    return x


if __name__ == "__main__":
    print("=" * 60)
    print("  Pohlig-Hellman DLP Solver")
    print("=" * 60)

    x = pohlig_hellman(g, h, p)

    print(f"\n[+] x = {x}")
    print(f"[+] 검증 (g^x mod p == h): {pow(g, x, p) == h}")

    flag_bytes = x.to_bytes((x.bit_length() + 7) // 8, "big")
    print(f"\n[+] FLAG: {flag_bytes.decode()}")

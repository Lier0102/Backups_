# UTCTF - Smooth Criminal 롸업

## 문제 개요

- **카테고리**: 암호학 (Cryptography)
- **주제**: 이산 로그 문제 (DLP) + Pohlig-Hellman 알고리즘

### 주어진 정보 (`dlp.txt`)

```
h = g^x mod p

p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517
```

`x`를 구해서 정수 → 바이트로 변환하면 FLAG가 나온다.

---

## 배경 지식

### 이산 로그 문제 (DLP, Discrete Logarithm Problem)

```
h = g^x mod p
```

- `g`: 생성원 (generator)
- `p`: 소수 모듈러스
- `h`: 공개된 값
- `x`: 우리가 구해야 할 비밀 지수

`g`와 `h`, `p`를 알고 있을 때 `x`를 구하는 문제가 DLP야.  
일반적으로 `p`가 충분히 크면 풀기 매우 어렵고, 이게 많은 공개키 암호의 안전성 근거야.

하지만 **`p-1`이 작은 소수들로만 이루어진 경우(smooth한 경우)**, Pohlig-Hellman 알고리즘으로 효율적으로 풀 수 있어.

---

### Smooth Number (부드러운 수)

어떤 수의 모든 소인수가 일정 bound `B` 이하일 때 **B-smooth**하다고 해.

이 문제에서:

```
p - 1 의 소인수 분해:
{2^3 * 3^3 * 5^3 * 7^2 * 11^3 * 13^3 * 17^3 * 19 * 23^2 * 29^2 * 31^3 * ...
 ... * 149^5 * ... * 191^5 * 193 * 197}

최대 소인수 = 197
```

`p`가 192비트짜리 큰 수인데도 `p-1`의 최대 소인수가 고작 `197`이야.  
이게 바로 "Smooth Criminal"이라는 제목의 의미야.

---

### Pohlig-Hellman 알고리즘

`p-1`이 smooth할 때 DLP를 효율적으로 풀 수 있는 알고리즘이야.

**핵심 아이디어:**

`p-1 = q1^e1 * q2^e2 * ... * qk^ek` 로 인수분해되면,

1. 각 소수 거듭제곱 `qi^ei` 에 대해 `x mod qi^ei` 를 따로 구한다.
2. 구한 나머지들을 **CRT(중국인의 나머지 정리)** 로 합쳐서 `x mod (p-1)` 을 복원한다.

각 `x mod q^e` 를 구하는 방법은 아래에서 설명한다.

---

### `x mod q^e` 구하기

`x`를 `q`진법으로 표현하면:

```
x = d_0 + d_1*q + d_2*q^2 + ... + d_(e-1)*q^(e-1)  (mod q^e)
```

각 자리 `d_k` 를 순서대로 구해서 합산한다.

**`d_k` 를 구하는 방법:**

먼저 위수(order)가 정확히 `q`인 원소 `γ`를 만든다:

```
γ = g^((p-1)/q)  mod p
```

그다음 `k`번째 자리를 구하기 위해:

```
x_k = d_0 + d_1*q + ... + d_(k-1)*q^(k-1)  (지금까지 구한 부분합)

h_k = (g^(-x_k) * h)^((p-1) / q^(k+1))  mod p
```

이렇게 하면 `h_k = γ^(d_k)` 가 되고,  
`d_k` 는 `0` ~ `q-1` 범위의 값이므로 `q`가 작은 소수이면 brute force로 바로 찾을 수 있어.

**왜 `h_k = γ^(d_k)` 가 되는가:**

```
h = g^x  이므로

h^((p-1)/q^(k+1)) = g^(x * (p-1)/q^(k+1))

x * (p-1)/q^(k+1) mod (p-1) 을 보면,
x = x_k + d_k*q^k + (더 높은 자리들) 에서
더 높은 자리들 * (p-1)/q^(k+1) 은 (p-1)의 배수가 되어 사라지고,
x_k * (p-1)/q^(k+1) 부분은 g^(-x_k) 를 곱해서 제거하면

결국 γ^(d_k) 만 남는다.
```

---

### CRT (중국인의 나머지 정리)

서로소인 모듈러스들에 대해 연립 합동식을 풀어주는 정리야.

```
x ≡ r_1  (mod m_1)
x ≡ r_2  (mod m_2)
...
x ≡ r_k  (mod m_k)
```

`m_1, m_2, ..., m_k` 가 쌍마다 서로소이면,  
`x mod (m_1 * m_2 * ... * m_k)` 가 유일하게 결정된다.

순차적으로 두 개씩 합치는 방식으로 구현할 수 있어:

```
x ≡ r_1  (mod m_1) 에서 시작
x ≡ r_2  (mod m_2) 와 합치려면

x = r_1 + m_1 * t  로 놓으면
r_1 + m_1 * t ≡ r_2  (mod m_2)
t ≡ (r_2 - r_1) * inverse(m_1, m_2)  (mod m_2)
```

---

## 풀이 흐름

```
1. p-1 소인수분해 → smooth 확인 → Pohlig-Hellman 적용 가능
2. 각 소수 거듭제곱 q^e 에 대해 x mod q^e 계산
   (γ = g^((p-1)/q) 로 각 자리 d_k 를 brute force)
3. CRT 로 전체 x mod (p-1) 복원
4. 검증: g^x mod p == h ?
5. x 를 바이트로 변환 → FLAG
```

---

## 풀이 코드 (`solve.py`)

```python
from sympy import factorint


p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517


def pohlig_hellman_prime_power(g, h, p, q, e):
    """
    x mod q^e 를 구한다.

    x = d_0 + d_1*q + ... + d_(e-1)*q^(e-1) 으로 표현하고,
    각 자리 d_k 를 순서대로 brute force로 찾는다.

    γ = g^((p-1)/q)  →  위수가 정확히 q인 원소
    h_k = (g^(-x_k) * h)^((p-1)/q^(k+1))  →  γ^(d_k) 와 같아짐
    d_k 는 0 ~ q-1 범위이므로 q가 작으면 빠르게 찾을 수 있음
    """
    order = p - 1
    gamma = pow(g, order // q, p)  # 위수 q 인 원소

    x = 0
    for k in range(e):
        g_inv_x = pow(g, (-x) % order, p)           # g^(-x_k) mod p
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

        x += d_k * (q ** k)

    return x % (q ** e)


def crt(remainders, moduli):
    """
    중국인의 나머지 정리로 연립 합동식을 푼다.
    x ≡ remainders[i]  (mod moduli[i])
    """
    x = remainders[0]
    m = moduli[0]
    for i in range(1, len(remainders)):
        r = remainders[i]
        mi = moduli[i]
        # t ≡ (r - x) * inverse(m, mi)  (mod mi)
        t = ((r - x) * pow(m, -1, mi)) % mi
        x = x + m * t
        m = m * mi
    return x % m


def pohlig_hellman(g, h, p):
    """
    Pohlig-Hellman 전체 흐름:
      1. p-1 소인수분해
      2. 각 q^e 에 대해 x mod q^e 계산
      3. CRT 로 전체 x 복원
    """
    order = p - 1
    factors = factorint(order)

    print(f"[*] p-1 최대 소인수: {max(factors.keys())}  → Smooth! Pohlig-Hellman 적용 가능")

    remainders = []
    moduli = []

    for q, e in factors.items():
        r = pohlig_hellman_prime_power(g, h, p, q, e)
        remainders.append(r)
        moduli.append(q ** e)
        print(f"    x ≡ {r:>15}  (mod {q}^{e} = {q**e})")

    print("\n[*] CRT 적용 중...")
    return crt(remainders, moduli)


if __name__ == "__main__":
    x = pohlig_hellman(g, h, p)

    print(f"\n[+] x        = {x}")
    print(f"[+] 검증 (g^x mod p == h): {pow(g, x, p) == h}")

    flag_bytes = x.to_bytes((x.bit_length() + 7) // 8, "big")
    print(f"\n[+] FLAG: {flag_bytes.decode()}")
```

---

## 실행 결과

```
[*] p-1 최대 소인수: 197  → Smooth! Pohlig-Hellman 적용 가능
    x ≡               5  (mod 2^3 = 8)
    x ≡              25  (mod 3^3 = 27)
    x ≡              82  (mod 5^3 = 125)
    ...
    x ≡            103  (mod 197^1 = 197)

[*] CRT 적용 중...

[+] x        = 810642462826781236630409314742801724164468986543937060322593530182136957
[+] 검증 (g^x mod p == h): True

[+] FLAG: utflag{sm00th_cr1m1nal_caught}
```

---

## FLAG

```
utflag{sm00th_cr1m1nal_caught}
```

---

## 핵심 포인트 정리

| 단계 | 내용 |
|---|---|
| Smooth 확인 | `p-1` 소인수분해 → 최대 소인수 197, 완전히 smooth |
| Pohlig-Hellman | `p-1 = ∏qi^ei` 이므로 각 `qi^ei` 별로 `x mod qi^ei` 를 독립적으로 계산 |
| 각 자리 복원 | `γ = g^((p-1)/q)` 로 위수 `q`짜리 원소 생성, `d_k` 를 brute force |
| CRT | 각 나머지를 합쳐 전체 `x` 복원 |
| 복호화 | `x` 를 big endian 바이트로 변환 → FLAG |

---

## DLP가 왜 어렵고, 이 문제에선 왜 쉬운가

### 일반적인 DLP가 어려운 이유

`h = g^x mod p` 에서 `x`를 구하려면:
- Brute force: `x`를 `0`부터 하나씩 대입 → `O(p)` 로 불가능
- Baby-step Giant-step: `O(√p)` → 그래도 `p`가 크면 불가능
- Index calculus: 현재 최선, 그래도 큰 소수에선 비현실적

이래서 `p`가 충분히 크면 DLP는 사실상 풀 수 없고,  
이게 **Diffie-Hellman**, **ElGamal**, **DSA** 같은 암호의 안전성 근거야.

### 이 문제에서 쉬운 이유

Pohlig-Hellman의 복잡도는 **`p-1`의 가장 큰 소인수 `q`에 의존**해:

```
O(∑ ei * (log(p) + √qi))  ≈  O(k * √qmax)
```

이 문제에서 `qmax = 197` 이므로:
- 각 소수에 대해 최대 197번만 brute force 하면 돼
- 소인수 개수가 많아도 각각 독립적으로 처리하므로 매우 빠름

### 교훈

> `p`가 크더라도 `p-1`이 작은 소수들로만 이루어진 **smooth prime**이면  
> Pohlig-Hellman으로 DLP가 쉽게 풀린다.

안전한 DLP 기반 암호를 만들려면 반드시 **`p-1`의 최대 소인수도 충분히 커야** 해.  
이런 소수를 **Safe Prime** (`p = 2q + 1`, `q`도 소수)이라고 부르고,  
실제 암호에서는 safe prime을 사용해야 해.

---

## 관련 개념 더 공부하기

- **Baby-step Giant-step**: DLP를 `O(√n)`에 푸는 범용 알고리즘
- **Index Calculus**: 현재 DLP에 대한 가장 빠른 알고리즘
- **Safe Prime**: `p = 2q + 1` (`q`도 소수) 형태의 안전한 소수
- **Diffie-Hellman**: DLP 기반 키 교환 프로토콜
- **Pohlig-Hellman 일반화**: 타원 곡선(ECDLP)에서도 동일하게 적용 가능
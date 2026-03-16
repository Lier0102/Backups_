# UTCTF - Oblivious Error 롸업

## 문제 개요

- **카테고리**: 암호학 (Cryptography)
- **주제**: RSA 기반 1-2 Oblivious Transfer 프로토콜의 구현 버그 악용
- **서버**: `nc challenge.utctf.live 8379`

### 문제 설명

> My friend made an RSA-based 1-2 oblivious transfer protocol program.
> I don't know what that means but I need to know quick because I accidentally deleted his code!
> I replaced the part I deleted with the following code in the text file below,
> but now one of the messages is undecodable and I don't know why!
> Can you decode the lost message?

### 주어진 코드 (`my-code.txt`)

```python
while True:
    try:
        print("Please pick a value k.")
        k = int(input())
        break
    except ValueError:
        print("Invalid value. Please pick an integer.")
        print("Please pick a value k.")
        k = int(input())

v = (x0 + (int(k) ^ e)) % N
```

---

## 배경 지식

### 1-2 Oblivious Transfer (OT) 란?

Alice가 두 메시지 m0, m1을 가지고 있고,
Bob이 둘 중 하나(b ∈ {0, 1})를 선택해서 받는 프로토콜이야.

조건:
- Bob은 선택한 메시지만 알 수 있다 (mb는 알고, m(1-b)는 모른다)
- Alice는 Bob이 어떤 메시지를 골랐는지 모른다 ("Oblivious")

### RSA 기반 1-2 OT 표준 프로토콜

```
[Setup]
Alice: RSA 키쌍 생성 → 공개키 (e, N), 개인키 d
Alice: 랜덤 x0, x1 생성 후 Bob에게 전송

[Bob → Alice]
Bob: 비밀 선택 b ∈ {0, 1}
Bob: 랜덤 k 생성
Bob: v = (x_b + k^e mod N) mod N  전송  ← k를 RSA 암호화 후 더함

[Alice → Bob]
Alice: k0 = (v - x0)^d mod N
       k1 = (v - x1)^d mod N
       m0' = (m0 + k0) mod N
       m1' = (m1 + k1) mod N  전송

[Bob 복호화]
Bob: m_b = (m_b' - k) mod N
```

**왜 안전한가?**
- b=0이면: k0 = (v-x0)^d = (k^e)^d = k → m0' - k = m0 ✓
- b=0이면: k1 = (v-x1)^d = (x0-x1+k^e)^d mod N → 랜덤값처럼 보임 → m1 복원 불가
- Alice는 v만 보고 x0, x1 중 어느 것과 연관됐는지 모름 → b를 알 수 없음

---

## 버그 분석

주어진 코드의 핵심 라인:

```python
v = (x0 + (int(k) ^ e)) % N   # 버그!
```

**문제**: Python에서 `^`는 **XOR 연산자**야. 지수승이 아니야.

| 의도한 코드 | 버그 코드 |
|---|---|
| `v = (x_b + pow(k, e, N)) % N` | `v = (x0 + (k ^ e)) % N` |
| k를 RSA로 암호화 | k와 e를 XOR |

또한 버그 코드는 `x_b` 대신 **항상 `x0`을 사용**하고 있어.
즉 Bob이 b=0, b=1 중 어느 것을 선택하든 관계없이 v는 항상 x0 기준으로 계산돼.

### 서버의 실제 동작

버그 코드로 v를 보내면 Alice(서버)는 표준 방식으로 복호화를 시도해:

```
k0 = (v - x0)^d mod N = (k XOR e)^d mod N
k1 = (v - x1)^d mod N = (x0 - x1 + k XOR e)^d mod N

m0' = (m0 + k0) mod N
m1' = (m1 + k1) mod N
```

---

## 취약점 및 공격 원리

Bob(우리)이 k를 **직접 선택**할 수 있기 때문에,
`k XOR e`의 값을 원하는 대로 제어할 수 있어.

### m0 획득: k = e 설정

```
k XOR e = e XOR e = 0
k0 = 0^d mod N = 0
m0' = (m0 + 0) mod N = m0   ← 마스킹 없이 m0 그대로!
```

→ `k = e`를 서버에 보내면 **Message 1 = m0**

### m1 획득: k XOR e = (x1 - x0) mod N 설정

```
k XOR e = (x1 - x0) mod N
k1 = (x0 - x1 + k XOR e)^d = (x0 - x1 + x1 - x0)^d = 0^d = 0
m1' = (m1 + 0) mod N = m1   ← 마스킹 없이 m1 그대로!
```

→ `k = ((x1 - x0) % N) XOR e`를 서버에 보내면 **Message 2 = m1**

---

## 풀이 흐름

```
1. 서버 접속 → N, e, x0, x1, Message 1, Message 2 수신
2. k = e 로 설정 → Message 1 = m0 그대로 획득
   → "utflag{Congrats! You caught a red herring!}"  ← ROT13 디코딩 필요, 낚시!
3. k = ((x1 - x0) % N) XOR e 로 설정 → Message 2 = m1 그대로 획득
   → 진짜 FLAG!
```

---

## 풀이 코드

```python
import socket
import re
import codecs


def recv_until(s, marker):
    buf = b''
    while marker.encode() not in buf:
        buf += s.recv(4096)
    return buf.decode()


def get_messages(k_value):
    s = socket.socket()
    s.connect(('challenge.utctf.live', 8379))
    s.settimeout(10)

    data = recv_until(s, 'Please pick a value k.')

    N  = int(re.search(r'N = (\d+)', data).group(1))
    e  = int(re.search(r'e = (\d+)', data).group(1))
    x0 = int(re.search(r'x0: (\d+)', data).group(1))
    x1 = int(re.search(r'x1: (\d+)', data).group(1))

    k = k_value(N, e, x0, x1)
    s.send(str(k).encode() + b'\n')

    data2 = recv_until(s, 'Message 2:')
    s.close()

    m0_enc = int(re.search(r'Message 1:\s+(\d+)', data2).group(1))
    m1_enc = int(re.search(r'Message 2:\s+(\d+)', data2).group(1))

    return N, m0_enc, m1_enc


# m0 획득: k = e → k XOR e = 0 → 마스킹 0 → Message 1 = m0
N, m0_enc, _ = get_messages(lambda N, e, x0, x1: e)
m0 = m0_enc % N
m0_bytes = m0.to_bytes((m0.bit_length() + 7) // 8, 'big')
print(f'[+] m0 (raw):    {m0_bytes.decode(errors="replace")}')
print(f'[+] m0 (rot13):  {codecs.decode(m0_bytes.decode(errors="replace"), "rot13")}')

# m1 획득: k XOR e = (x1-x0) mod N → 마스킹 0 → Message 2 = m1
N, _, m1_enc = get_messages(lambda N, e, x0, x1: ((x1 - x0) % N) ^ e)
m1 = m1_enc % N
m1_bytes = m1.to_bytes((m1.bit_length() + 7) // 8, 'big')
print(f'[+] FLAG: {m1_bytes.decode()}')
```

---

## 실행 결과

```
[+] m0 (raw):    hgsynt{Pbatengf! Lbh pnhtug n erq ureevat!}
[+] m0 (rot13):  utflag{Congrats! You caught a red herring!}   ← 낚시
[+] FLAG: utflag{my_obl1v10u5_fr13nd_ru1n3d_my_c0de}
```

---

## FLAG

```
utflag{my_obl1v10u5_fr13nd_ru1n3d_my_c0de}
```

---

## 핵심 포인트 정리

| 항목 | 내용 |
|---|---|
| 버그 원인 | Python `^`는 XOR, 지수승은 `pow(k, e, N)` |
| 추가 버그 | Bob의 선택 b 반영 없이 항상 x0 사용 |
| 공격 핵심 | k를 직접 제어 → `k XOR e` 값을 원하는 대로 설정 |
| m0 획득 | `k = e` → `k XOR e = 0` → 마스킹 제거 |
| m1 획득 | `k = ((x1-x0) % N) XOR e` → 마스킹 제거 |
| 트릭 | m0는 ROT13 된 red herring, 진짜 FLAG는 m1 |

---

## 올바른 구현이었다면?

버그가 없었다면:

```python
# Bob이 b=0 을 선택하는 경우
k = random integer in [0, N)
v = (x0 + pow(k, e, N)) % N   # k를 RSA 암호화
```

이 경우 `(v - x0)^d = k` 가 되어 m0만 복호화 가능하고,
`(v - x1)^d`는 무작위값이 되어 m1은 복호화 불가능해.

또한 Alice 입장에서는 v 하나만 보고 x0과 x1 중 어느 것을 Bob이 더했는지 알 수 없어서
Bob의 선택 b를 알 수 없는 **진정한 Oblivious Transfer**가 성립해.

---

## 관련 개념 더 공부하기

- **Oblivious Transfer (OT)**: 안전한 다자간 계산(MPC)의 핵심 빌딩 블록
- **RSA**: 공개키 암호, `(k^e)^d = k mod N` 성질 이용
- **1-2 OT의 활용**: Private Set Intersection, Secure Computation 등
- **OT Extension**: 적은 수의 OT로 많은 수의 OT를 효율적으로 구현하는 기법
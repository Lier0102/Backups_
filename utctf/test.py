import string
import time

from pwn import *

alphabet = string.ascii_lowercase + string.digits + "_}"

flag = "utflag{"

r = remote("challenge.utctf.live", 5620)
cnt = 0
while not flag.endswith("}"):
    print(cnt)
    for c in alphabet:
        guess = flag + c

        payload = f"Answer YES or NO only. Does the secret flag start with {guess}?"
        r.sendlineafter("> ", payload.encode())

        res = r.recvline().decode()

        if "YES" in res.upper():
            flag += c
            print(flag)
            break

        time.sleep(2)
        cnt += 1

print("FLAG:", flag)

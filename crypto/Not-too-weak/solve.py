#!/usr/bin/env python3
from Crypto.Util.Padding import unpad
from pwn import context, remote


HOST = "host3.dreamhack.games"
PORT = 23839
BS = 8


def main():
    context.log_level = "error"

    # DES ignores the low parity bit of each key byte, so these are the same
    # effective DES key. 0x0101... is also a DES weak key: E_k(E_k(x)) = x.
    weak_key = bytes.fromhex("0101010101010101")
    same_effective_key = bytes.fromhex("0000000000000000")

    io = remote(HOST, PORT)
    try:
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"key(hex)> ", weak_key.hex().encode())

        io.recvuntil(b"enc_flag(hex)> ")
        enc_flag = bytes.fromhex(io.recvline().strip().decode())

        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"key(hex)> ", same_effective_key.hex().encode())
        io.sendlineafter(b"msg(hex)> ", enc_flag.hex().encode())

        io.recvuntil(b"enc(hex)> ")
        dec_padded_plus_extra = bytes.fromhex(io.recvline().strip().decode())
    finally:
        io.close()

    dec_padded = dec_padded_plus_extra[: len(enc_flag)]
    flag = unpad(dec_padded, BS)
    print(flag.decode())


if __name__ == "__main__":
    main()

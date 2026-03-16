#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import socket
import sys
import time
from typing import Iterable

DEFAULT_HOST = "challenge.utctf.live"
DEFAULT_PORT = 7255


def recv_some(
    sock: socket.socket, delay: float = 0.15, chunk_size: int = 4096
) -> bytes:
    time.sleep(delay)
    out = bytearray()
    while True:
        try:
            data = sock.recv(chunk_size)
            if not data:
                break
            out.extend(data)
            if len(data) < chunk_size:
                break
        except socket.timeout:
            break
    return bytes(out)


def printable(data: bytes, keep_unicode: bool = True) -> str:
    if keep_unicode:
        return data.decode("utf-8", errors="replace")
    return data.decode("latin1", errors="replace")


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def send_line(sock: socket.socket, line: str | bytes) -> None:
    if isinstance(line, str):
        line = line.encode()
    if not line.endswith(b"\n"):
        line += b"\n"
    sock.sendall(line)


def banner_probe(args: argparse.Namespace) -> int:
    with connect(args.host, args.port, args.timeout) as sock:
        data = recv_some(sock, delay=args.delay)
        sys.stdout.write(printable(data, keep_unicode=not args.latin1))
    return 0


def scripted_probe(args: argparse.Namespace) -> int:
    with connect(args.host, args.port, args.timeout) as sock:
        data = recv_some(sock, delay=args.delay)
        if data:
            print("[recv:init]")
            print(
                printable(data, keep_unicode=not args.latin1),
                end="" if data.endswith(b"\n") else "\n",
            )

        for idx, item in enumerate(args.lines, 1):
            print(f"[send:{idx}] {item!r}")
            send_line(sock, item)
            data = recv_some(sock, delay=args.delay)
            print(f"[recv:{idx}]")
            if args.hex:
                print(hexdump(data))
            else:
                print(
                    printable(data, keep_unicode=not args.latin1),
                    end="" if data.endswith(b"\n") else "\n",
                )
    return 0


def name_probe(args: argparse.Namespace) -> int:
    payload: bytes
    if args.pattern is not None:
        payload = (
            args.pattern.encode()
            * ((args.length + len(args.pattern) - 1) // len(args.pattern))
        )[: args.length]
    else:
        payload = args.byte.encode() * args.length

    with connect(args.host, args.port, args.timeout) as sock:
        init = recv_some(sock, delay=args.delay)
        print("[recv:init]")
        print(
            printable(init, keep_unicode=not args.latin1),
            end="" if init.endswith(b"\n") else "\n",
        )

        print(f"[send:name] len={len(payload)}")
        send_line(sock, payload)

        out = recv_some(sock, delay=args.delay)
        print("[recv:name]")
        if args.hex:
            print(hexdump(out))
        else:
            print(
                printable(out, keep_unicode=not args.latin1),
                end="" if out.endswith(b"\n") else "\n",
            )

        if args.exit_after_name:
            send_line(sock, "n")
            out2 = recv_some(sock, delay=args.delay)
            print("[recv:exit]")
            if args.hex:
                print(hexdump(out2))
            else:
                print(
                    printable(out2, keep_unicode=not args.latin1),
                    end="" if out2.endswith(b"\n") else "\n",
                )
    return 0


def format_probe(args: argparse.Namespace) -> int:
    payload = args.payload
    with connect(args.host, args.port, args.timeout) as sock:
        init = recv_some(sock, delay=args.delay)
        print("[recv:init]")
        print(
            printable(init, keep_unicode=not args.latin1),
            end="" if init.endswith(b"\n") else "\n",
        )

        print(f"[send:name] {payload!r}")
        send_line(sock, payload)

        out = recv_some(sock, delay=args.delay)
        print("[recv:name]")
        if args.hex:
            print(hexdump(out))
        else:
            text = printable(out, keep_unicode=not args.latin1)
            print(text, end="" if out.endswith(b"\n") else "\n")

            if args.extract_hex:
                found = re.findall(r"0x[0-9a-fA-F]+", text)
                if found:
                    print("[parsed:pointers]")
                    for item in found:
                        print(item)
    return 0


def raw_interactive(args: argparse.Namespace) -> int:
    with connect(args.host, args.port, args.timeout) as sock:
        init = recv_some(sock, delay=args.delay)
        if init:
            sys.stdout.write(printable(init, keep_unicode=not args.latin1))
            sys.stdout.flush()

        try:
            while True:
                line = sys.stdin.buffer.readline()
                if not line:
                    break
                sock.sendall(line)
                out = recv_some(sock, delay=args.delay)
                if out:
                    sys.stdout.write(printable(out, keep_unicode=not args.latin1))
                    sys.stdout.flush()
        except KeyboardInterrupt:
            pass
    return 0


def repeat(items: Iterable[str], count: int) -> list[str]:
    out: list[str] = []
    for _ in range(count):
        out.extend(items)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Reusable probing helper for the UTCTF Small-Blind poker service."
    )
    p.add_argument(
        "--host", default=DEFAULT_HOST, help=f"remote host (default: {DEFAULT_HOST})"
    )
    p.add_argument(
        "--port",
        default=DEFAULT_PORT,
        type=int,
        help=f"remote port (default: {DEFAULT_PORT})",
    )
    p.add_argument(
        "--timeout", default=1.0, type=float, help="socket timeout in seconds"
    )
    p.add_argument(
        "--delay", default=0.15, type=float, help="sleep before draining recv buffer"
    )
    p.add_argument(
        "--latin1", action="store_true", help="decode output as latin1 instead of utf-8"
    )
    p.add_argument("--hex", action="store_true", help="print responses as hexdump")

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("banner", help="only receive the initial prompt")

    sp = sub.add_parser("script", help="send a scripted sequence of lines")
    sp.add_argument("lines", nargs="+", help="lines to send")

    np = sub.add_parser("name", help="probe the name input with a controlled payload")
    np.add_argument("-n", "--length", type=int, default=128, help="payload length")
    np.add_argument("-b", "--byte", default="A", help="single-byte filler string")
    np.add_argument(
        "-p", "--pattern", help="repeating pattern instead of a single byte"
    )
    np.add_argument(
        "--exit-after-name",
        action="store_true",
        help="send n after the name to force a clean exit",
    )

    fp = sub.add_parser(
        "fmt", help="send a candidate format-string payload as the name"
    )
    fp.add_argument("payload", help='example: "%p %p %p %p"')
    fp.add_argument(
        "--extract-hex", action="store_true", help="extract 0x... tokens from response"
    )

    ip = sub.add_parser(
        "interactive", help="simple stdin/stdout loop for manual probing"
    )

    ap = sub.add_parser("autoplay", help="send a quick canned play sequence")
    ap.add_argument("--name", default="test", help="player name")
    ap.add_argument(
        "--actions",
        nargs="*",
        default=["y", "call", "check", "check", "check", "n"],
        help="lines to send after the name",
    )
    ap.add_argument(
        "--repeat", type=int, default=1, help="repeat the actions list this many times"
    )

    return p


def autoplay_probe(args: argparse.Namespace) -> int:
    lines = [args.name] + repeat(args.actions, args.repeat)
    with connect(args.host, args.port, args.timeout) as sock:
        data = recv_some(sock, delay=args.delay)
        if data:
            print("[recv:init]")
            print(
                printable(data, keep_unicode=not args.latin1),
                end="" if data.endswith(b"\n") else "\n",
            )

        for idx, item in enumerate(lines, 1):
            print(f"[send:{idx}] {item!r}")
            send_line(sock, item)
            out = recv_some(sock, delay=args.delay)
            print(f"[recv:{idx}]")
            if args.hex:
                print(hexdump(out))
            else:
                print(
                    printable(out, keep_unicode=not args.latin1),
                    end="" if out.endswith(b"\n") else "\n",
                )
    return 0


def main() -> int:
    args = build_parser().parse_args()

    if args.cmd == "banner":
        return banner_probe(args)
    if args.cmd == "script":
        return scripted_probe(args)
    if args.cmd == "name":
        return name_probe(args)
    if args.cmd == "fmt":
        return format_probe(args)
    if args.cmd == "interactive":
        return raw_interactive(args)
    if args.cmd == "autoplay":
        return autoplay_probe(args)

    raise SystemExit(f"unknown subcommand: {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())

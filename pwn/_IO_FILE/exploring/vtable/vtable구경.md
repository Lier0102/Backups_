# !! 잘못된 점이 있을 경우 알려주세요 !!
.. 저는 뭐가 잘못됐는지 아직 모르거든요..


다른 FSOP를 공부하셔서 올리시는 분들과 달리 저는 그 정도의 끈기가 없습니다.  
흥미도 없고요, 그래서 나름대로 찾아본 내용을 정리하려 합니다.  
정리를 잘하는 편이냐고 한다면 당연히 아니고요..   
그런데도 읽기 편하셨다면 그건 다행인 거겠네요..

**목차**

1. `정적 분석`
2. `동적 분석`
3. `익스플로잇`
4. `참조 & 정리`

목차가 간결한 것도 앞서 말한 이유 때문입니다...ㅋㅋ

바로 `vtable`로 넘어가면 제가 버티지 못하니..  
**`임의 주소에 값 쓰기`**, **`임의 주소로부터 값 읽어 출력하기`** 를 다룬 뒤에  
`vtable`(glibc 2.28+ 기준)을 정리해 보겠습니다.

# 1. `정적 분석`
시작부터 구조체 보기는 아무래도 좀 그렇죠..? 그래도 어쩔 수 없습니다.  
`_IO_FILE_plus`는 다음과 같이 생겼습니다.  

```c
struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};
```
`FILE` 구조체 하나, `_IO_jump_t` 구조체 하나 보이네요..  
`vtable` 친구는 `vtable`을 가리키는 포인터..고요  
말이 이상한데. 암튼 그렇습니다. `FILE` 구조체에 중점을 맞춰 지금은 설명하겠습니다.  

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

`FILE`은 사실 `_IO_FILE`이란 이름을 가진 구조체입니다.  
크기가 심상치 않아 분석이 어렵지 않았냐고요? 전혀 아닙니다 ㅋㅋ.. 구라임. 개힘듦.  

저는 여기서 묘책을 하나 발동하겠습니다.  
지금 실험해 볼 프로그램은 **두 개**입니다.  

하나는 **`fread`와 `fopen`을 활용한 `50,000`번의 읽어오는 행위**,   
다른 하나는 **`read`, `open`을 활용하여 `50,000`번의 읽어오는 동작**  
...를(을) 수행하는 녀석..들입니다.  

```c
// gcc fread_loop.c -o fread_loop.bin
#include <stdio.h>

int main(int argc, char **argv) {
    char buf[0x1000];
    FILE *fp = fopen("/dev/urandom", "r");

    for (int i = 0; i < 50000; i++) {
        fread(buf, 1, 0x20, fp);
    }
    
    return 0;
}
```

```c
// gcc read_loop.c -o read_loop.bin
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    char buf[0x1000];

    int fd = open("/dev/urandom", O_RDONLY);
    for (int i = 0; i < 50000; i++) {
        read(fd, buf, 0x20);
    }
    
    return 0;
}
```

원래는 귀찮아서 `gcc`로 컴파일만 대충 때려서 a.out으로 돌리는데..  
한 폴더에 저는 담아둘 거라 이름을 소중하게 붙여줬습니다..ㅋㅋ  

이제 저 두 녀석으로 뭘 할까요?  
첫 번째는 바로... **시간 측정** 입니다!!  
```bash
[ BANKAI >:3 ]$ time ./fread_loop.bin
real    0m0.014s
user    0m0.000s
sys     0m0.005s
```

```bash
[ BANKAI >:3 ]$ time ./read_loop.bin
real    0m0.023s
user    0m0.003s
sys     0m0.019s
```

왜 `fread`, 그리고 `fopen`이 더 빠를까요?  
음.. 당연한 거지만 굳이 설명하자면,  
결국엔 둘 다 `open`, `read` syscall을 사용합니다.   
문제는 **어떻게** 사용하느냐, 죠..  

`read_loop.c` 부터 얘기해 볼까요?  
이 친구는 `50,000`번에 걸쳐 `read()`를 그냥 바로 호출합니다.  
`read` syscall만 남발하는 셈이죠..  

**반면에**, `fread_loop.c`는 **효율적으로** 운영됩니다.  
필요한 순간에만 `read` syscall을 날려요, 이게!!  

```bash
# read_loop
[ BANKAI >:3 ]$ strace ./read_loop.bin 2>&1 | grep -E "^read" | wc -l
50001
```

```bash
# fread_loop
[ BANKAI >:3 ]$ strace ./fread_loop.bin 2>&1 | grep -E "^read" | wc -l
392
```

.. 진짜 엄청나지 않나요??

어떻게 이게 될 수 있는지 간단하게 짚고 넘어가자면,  

1. `_IO_FILE` 구조체
2. `커널 모드` vs `유저 모드`

크게 본다면 이렇게 됩니다. `read`는 시스템 콜을 직접 사용한다고 했는데..  
이게 일어나면 `컨텍스트 스위칭`이 일어나게 됩니다.   

커널이 데이터를 가져와 유저의 메모리에 복사하는데...  
이게 **`50,000`번** 반복되면 그만큼 비용이 많이 발생한다는 거죠!  

`_IO_FILE` 구조체 같은 경우,  
`라이브러리`에서 할당한 내부 버퍼를 사용합니다. 바로 버퍼링을 위해서..!  
필요한 만큼 읽고, 필요한 만큼 쓰는.. 여기서 바로 구체적으로 설명하진 않지만  
**상당히** 고능합니다. 이게아닌가;;  

감은 잡혔으니, 바로 `임의 주소에 쓰기`와 `임의 주소 읽기`를 알아보겠습니다.  
하지만, 여기서는 코드를 다루지 않겠습니다. 직접 읽고 오시는 걸 추천드립니다..  
저만 고생할 순 없거든요.  

읽고 오신 경우엔 아래 내용을 떠올리시면 됩니다. 제가 기억력이 안 좋은 편이라..  

## 임의로 읽을 때
(fwrite같은 걸로 읽어서 그 주소에 있는 숨겨진 값 같은 거 볼 때를 의미함)
- `_flags` 설정해야함
- `write_base`에 쓸 곳의 주소를 적어야함
- `write_ptr`에 주소+길이
- `read_end = write_base`
- `buf_end - buf_base` >= `쓸 바이트 수`

## 임의로 쓸 때
- `_flags` 설정해야함
- `read_ptr` == `read_end` 여야함
- `buf_base`를 쓸 곳의 주소로 적어야함
- `buf_end`는 `buf_base`에 넣은 주소 + 해당하는 값의 크기(알맞게 정하지 않으면 라이브러리에서 임의로 적당히 큰 거 할당함)
- `buf_end - buf_base` >= `읽을 바이트 수`

다른 여러 변수들 전~부 고민할 필요 없이, `buf_base`, ` buf_end`를 제외한 녀석들은 전부 `NULL`로!  
이 둘만 읽을 곳으로 잘 정해주면 됨  
  
ex) win 변수를 조작할 때
`buf_base` = `win`의 시작주소  
`buf_end` = `win`의 시작주소 + `win`의 크기

(작성중)

# 정리
(작성중)

# 참고
[pwn.college 파일 구조체 강의](https://pwn.college/software-exploitation/file-struct-exploits)  
[드림핵 FSOP 강의](https://dreamhack.io/lecture/units/glibc-fsop)
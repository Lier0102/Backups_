# 환경
`patchelf`로 바이너리를 패치한 뒤 적절한 환경에서 돌려보겠음.. 
주어진 `Dockerfile`로 빌드하고  
`ld-linux-x86-64.so.2`와 `libc.so.6`을 꺼내면 됨  

꺼낸 걸로 패치 ㄱㄱ
```bash
patchelf --set-interpreter ld-linux-x86-64.so.2
patchelf --replace-needed libc.so.6
```

원본이랑 패치된 거랑 따로 분리하는 게 정석임..  
여기선 그러지 않았음

# 정적분석
지금 배우고 있는 중이라 드림핵에 나온 문제 태그를 토대로 분석을 진행함  
`DFB`는 `free()`는 하지만 포인터를 `NULL`로 초기화하지 않음..  
여기서 찾았고, `FSOP` 태그... 사실 이 문제도 `FSOP` 공부의 토대로 삼을 셈이었음.  
그런데 냅다 `FSOP`만 찾으려 하니까 안 찾아짐, 그러나 힙 익스 하다가 찾음.  
그러니까.. 솔직히 말하면 문제는 힙 익스에 맞춰짐.   
덮을 수 있는 것들 중에 `stdout/stderr/stdin` 이 포함되어 있었다..

```c
int print_menu()
{
  puts("1. Get a cat");
  puts("2. See a cat");
  puts("3. Pet a cat");
  puts("4. Release a cat");
  puts("5. Get a dog");
  puts("6. See a dog");
  puts("7. Pet a dog");
  puts("8. Release a dog");
  puts("9. Exit");
  return printf("Enter your choice: ");
}
```
메뉴는 간단함. 또한 코드도 복잡하지 않았음.  

각 메뉴의 동작이 `cat/dog/exit` 이렇게 구분되어 있다고 생각하면 됨.  
그러므로 `cat` 계열 분석하고, 나머지는 코드로 분석하지 않겠음.  

## 1. `get_cat()`
**분석은 `IDA`로 진행됨**
`get_cat()`의 처음 부분에는 아래 코드가 있음.  

```c
printf("Enter index (0-%d) to get a cat: ", 15);
__isoc99_scanf("%d", &v2);
```

그리고 첫 조건 쌍은 이러함.  
```c
if ( v2 < 0x10 ) {...}
else
  {
    puts("Invalid index!");
  }
```

`if`문 안에는,
```c
if ( cats_occupied[v2] )
    {
      printf("A cat alraedy occupied index %d!\n", v2);
    }
    else
    {
      v0 = v2;
      cats[v0] = malloc(0x90uLL);
      cats_occupied[v2] = 1;
      printf("A cat now occupies %d!\n", v2);
    }
```
즉, `0x10`보다 작은 인덱스라면  
`cats_occupied[해당 인덱스]`가 `1`인지 확인하고 그렇지 않다면 메모리를 할당해 줌.  

여기서는 딱히 문제될 게 없다고 판단  

## 2. `see_cat()`
`get_cat()`과 같이 인덱스를 받음.  
인덱스 검사 또한 위와 동일, 구체적으로는  
```c
if ( v1 < 0x10 )
  {
    printf("A cat says: ");
    write(1, (const void *)cats[v1], 0x90uLL);
  }
  else
  {
    puts("Invalid index!");
  }
```
이렇게 생김. `0x90`만큼 할당해 줬으니, 보여줄 때도 `0x90`만큼 보여주는 듯함.  
문제는 **`cats`가 할당 해제되었을 때, 접근이 가능하단 점임**

## 3. `pet_cat()`
유효성 검사 자체는 똑같을 뻔 했는데, `cats_occupied[idx]`를 활용해 존재 여부를 판단함.  

```c
if ( v1 < 0x10 && cats_occupied[v1] )
  {
    printf("Show me your word: ");
    read(0, (void *)cats[v1], 0x90uLL);
  }
  else
  {
    puts("Invalid index!");
  }
```
그러고선 `0x90`만큼 입력을 받음. 이 녀석도 `see_cat()`과 동일한 문제를 가짐.  

## 4. `rel_cat()`
대망의 마지막 함수.  
```c
if ( v1 < 0x10 )
  {
    free((void *)cats[v1]);
    cats_occupied[v1] = 0;
    printf("A cat at index %d is now released!\n", v1);
  }
  else
  {
    puts("Invalid index!");
  }
```
존재하는지 판단도 제대로 하지 않고 해제시켜줌. `입력값 < 0x10`이 조건이라..  
`UAF` 가능 ㅋ

`***_dog()` 친구들은 크기(`0x100`), 그리고 최대 생성 가능한 수량이 `2개`라는 점을 빼면 로직이 똑같음.  

여기까지 보고 생각할 수 있는 점은  
그냥 다 먹을 수 있다. 그 점임.  



# 동적분석
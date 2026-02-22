// gcc main.c -o main -z relro -z now
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

int main()
{
    init();
    FILE *fp = fopen("./dummy", "r");
    printf("printf: %p\n", printf);
    printf("fp: %p\n", fp);
    printf("FSOP?: ");
    read(0, fp, 0x1f0);
    fseek(fp, 0, SEEK_END);
}
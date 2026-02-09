#include <stdio.h>

int main() {
    char c;

    scanf("%c", &c);
    if (c == 'N' || c == 'n') {
        puts("Naver D2");
    } else {
        puts("Naver Whale");
    }

    return 0;
}
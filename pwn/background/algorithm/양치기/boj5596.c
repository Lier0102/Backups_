#include <stdio.h>

int main() {
    int a=0, b=0;

    for (int i = 0; i < 4; i++) {
        int t;
        scanf("%d", &t);
        a += t;
    }

    for (int i = 0; i < 4; i++) {
        int t;
        scanf("%d", &t);
        b += t;
    }

    printf("%d\n", a >= b ? a : b);
}
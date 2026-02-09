#include <stdio.h>

int main() {
    int t1, t2;
    scanf("%d %d", &t1, &t2);

    printf("%d\n", t1 <= t2 ? t1 : t2);

    return 0;
}
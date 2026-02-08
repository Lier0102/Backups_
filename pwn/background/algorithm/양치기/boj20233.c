#include <stdio.h>

int main() {
    int a, x, b, y, t;

    scanf("%d%d%d%d%d", &a,&x, &b, &y, &t);

    int c1 = a;
    if (t > 30) {
        c1 += (t- 30) * x * 21;
    }

    int c2 = b;
    if (t > 45) {
        c2 += (t - 45) * y * 21;
    }

    printf("%d %d\n", c1, c2);
}
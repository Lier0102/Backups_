#include <stdio.h>

int main() {
    int t;scanf("%d", &t);

    if (t % 10 != 0) {
        puts("-1"); return 0;
    }

    int a=300, b=60, c=10;
    int ra, rb, rc; // result for the a, b, and c ; 

    ra = t / a;
    t %= a;

    rb = t / b;
    t %= b;

    rc = t / c;
    t %= c;

    printf("%d %d %d", ra, rb, rc);

    return 0;
}
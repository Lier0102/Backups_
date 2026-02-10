#include <stdio.h>

int main() {
    int x1, y1, x2, y2, x3, y3;
    int resx, resy;

    scanf("%d %d", &x1, &y1);
    scanf("%d %d", &x2, &y2);
    scanf("%d %d", &x3, &y3);

    resx = x1 ^ x2 ^ x3;
    resy = y1 ^ y2 ^ y3;

    printf("%d %d", resx, resy);

    return 0;
}
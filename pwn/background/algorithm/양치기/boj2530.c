#include <stdio.h>

int main() {
    int h, m, s, d;
    scanf("%d %d %d", &h, &m, &s);
    scanf("%d", &d);

    long long res = (long long)h * 3600 + m * 60 + s;

    res += d;

    res %= 86400; // 24h

    h = res / 3600;
    m = (res / 60) % 60;
    s = res % 60;

    printf("%d %d %d\n", h, m, s);

    return 0;
}
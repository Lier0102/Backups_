#include <stdio.h>

int main() {
    int n;
    scanf("%d", &n);

    int res = 1000 - n;
    int c[] = {500, 100, 50, 10, 5, 1};
    int cnt = 0;

    for (int i = 0; i < 6; i++) {
        cnt += res / c[i];
        res %= c[i];
    }

    printf("%d", cnt);

    return 0;
}
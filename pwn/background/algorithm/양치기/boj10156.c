#include <stdio.h>

int main() {
    int n, k, m;
    scanf("%d %d %d", &k, &n, &m);

    int sum = k * n;
    int res = sum - m;

    if (res < 0) {
        puts("0");
    } else {
        printf("%d", res);
    }

    return 0;
}
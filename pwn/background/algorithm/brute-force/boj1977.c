#include <stdio.h>

int main() {
    int m, n;
    int sum = 0;
    int min = -1;
    scanf("%d %d", &m, &n);

    for (int i = 1; i <= 100; i++) {
        int tmp = i * i;

        if (tmp >= m && tmp <= n) {
            sum += tmp;

            if (min == -1) {
                min = tmp;
            }
        }
    }

    if (min == -1) {
        puts("-1");
    } else {
        printf("%d\n%d", sum, min);
    }

    return 0;
}
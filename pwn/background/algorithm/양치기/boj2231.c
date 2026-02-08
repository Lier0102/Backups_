#include <stdio.h>

int main() {
    int n;
    int res = 0;
    scanf("%d", &n);

    for (int i = 1; i < n; i++) {
        int sum = i;
        int tmp = i;

        while (tmp > 0) {
            sum += tmp % 10;
            tmp /= 10;
        }

        if (sum == n) {
            res = i;
            break;
        }
    }

    printf("%d\n", res);

    return 0;
}
#include <stdio.h>

int solve(int n) {
    int sum = 0;

    while (n > 0) {
        sum += n % 10;
        n /= 10;
    }

    return sum;
}

int main() {
    int n;
    int cnt = 0;

    scanf("%d", &n);

    for (int i = 1; i <= n; i++) {
        int sum = solve(i);

        if (i % sum == 0) {
            cnt++;
        }
    }

    printf("%d\n", cnt);
}
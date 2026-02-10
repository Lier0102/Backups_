#include <stdio.h>

int solve(int n) {
    int cnt = 0;

    while (n > 0) {
        int a = n % 10;

        if (a == 3 || a == 6 || a == 9) {
            cnt++;
        }
        n /= 10;
    }
    
    return cnt;
}

int main() {
    int n;
    long long res = 0;

    scanf("%d", &n);

    for (int i = 1; i <= n; i++) {
        res += solve(i);
    }

    printf("%lld", res);

    return 0;
}
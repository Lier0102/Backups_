#include <stdio.h>

// a + b + c = n
// c >= b + 2
// a, b, c >= 1
// a mod 2 =>? 0

int n;

int solve() {
    int cnt = 0;

    for (int a = 1; a <= n; a++) {
        for (int b = 1; b <= n; b++) {
            for (int c = 1; c <= n; c++) {
                if (a + b + c == n) {
                    if (a % 2 == 0) {
                        if (c >= b + 2) {
                            cnt++;
                        }
                    }
                }
            }
        }
    }

    return cnt;
}

int main() {
    scanf("%d", &n);

    printf("%d", solve());

    return 0;
}
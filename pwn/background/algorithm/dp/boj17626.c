#include <stdio.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

int dp[50001];

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 1; i <= n; i++) {
        dp[i] = i;

        for (int j = 1; j * j <= i; j++) {
            dp[i] = MIN(dp[i], dp[i - j * j] + 1);
        }
    }

    printf("%d\n", dp[n]);

    return 0;
}
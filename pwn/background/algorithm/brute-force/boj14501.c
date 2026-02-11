#include <stdio.h>

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

int n;
int t[16], pr[16];
int max = 0;

void solve(int d, int p) { // day and profit
    if (d == n + 1) {
        max = MAX(max, p);
        return;
    }

    if (d > n + 1) return;

    if (d + t[d] <= n + 1) {
        solve(d + t[d], p + pr[d]);
    }

    solve(d + 1, p);
}

int main() {
    scanf("%d", &n);
    for (int i = 1; i <= n; i++) {
        scanf("%d %d", &t[i], &pr[i]);
    }

    solve(1, 0);

    printf("%d\n", max);

    return 0;
}
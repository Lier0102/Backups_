#include <stdio.h>

long long p[101];

void solve() {
    int n;
    scanf("%d", &n);
    printf("%lld\n", p[n]);
}

int main() {
    p[1] = 1; p[2] = 1;
    p[3] = 1; p[4] = 2;
    p[5] = 2;

    for (int i = 6; i <= 100; i++) {
        p[i] = p[i - 1] + p[i - 5];
    }

    int t;
    scanf("%d", &t);
    while (t--) {
        solve();
    }

    return 0;
}
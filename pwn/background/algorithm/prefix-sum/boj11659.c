#include <stdio.h>

// s(i, j) = sum[j] - sum[i - 1];
// well-known

int main() {
    int n, m;
    int a[100001];
    long long sum[100001] = {0};

    scanf("%d %d", &n, &m);

    for (int i = 1; i <= n; i++) {
        scanf("%d", &a[i]);
        sum[i] = sum[i - 1] + a[i];
    }

    for (int i = 0; i < m; i++) {
        int v1, v2;
        scanf("%d %d", &v1, &v2);

        printf("%lld\n", sum[v2] - sum[v1 - 1]);
    }

    return 0;
}

// https://ittrue.tistory.com/567
// reference
#include <stdio.h>

int gcd(int a, int b) {
    while (b != 0) {
        int r = a % b;
        a = b;
        b = r;
    }

    return a;
}

int tree[100001];
int gap[100001];

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        scanf("%d", &tree[i]);
    }

    for (int i = 0; i < n - 1; i++) {
        gap[i] = tree[i + 1] - tree[i];
    }

    int g = gap[0];

    for (int i = 1; i < n - 1; i++) {
        g = gcd(g, gap[i]);
    }

    long long res = (long long)(tree[n-1] - tree[0]) / g;
    printf("%lld", res - (n - 1));

    return 0;
}
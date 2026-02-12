#include <stdio.h>

long long tree[1000001];

int main() {
    int n;
    long long m;
    long long max = 0;

    scanf("%d %lld", &n, &m);

    for (int i = 0; i < n; i++) {
        scanf("%lld", &tree[i]);
        if (tree[i] > max) max = tree[i];
    }

    long long low = 0, high = max;
    long long res = 0;

    while (low <= high) {
        long long mid = (low + high) / 2;
        long long sum = 0;

        for (int i = 0; i < n; i++) {
            if (tree[i] > mid) {
                sum += (tree[i] - mid);
            }
        }

        if (sum >= m) {
            res = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    printf("%lld", res);
}
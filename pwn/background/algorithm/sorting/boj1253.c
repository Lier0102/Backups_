#include <stdio.h>
#include <stdlib.h>

int comp(const void *a, const void *b) {
    return (*(long long *)a) - (*(long long *)b);
}

int main() {
    int n;
    long long *a;
    scanf("%d", &n);

    a = (long long *)malloc(sizeof(long long) * n);

    for (int i = 0; i < n; i++) {
        scanf("%lld", &a[i]);
    }

    qsort(a, n, sizeof(long long), comp);

    // for (int i = 0; i < n; i++) {
    //     printf("%d ", a[i]);
    // }

    int cnt = 0;

    for (int i = 0; i < n; i++) {
        long long v = a[i];
        int left = 0, right = n - 1;

        while (left < right) {
            long long sum = a[left] + a[right];

            if (left == i) {
                left++;
                continue;
            }

            if (right == i) {
                right--;
                continue;
            }

            if (sum == v) {
                cnt++;
                break;
            } else if (sum < v) {
                left++;
            } else {
                right--;
            }
        }
    }

    printf("%d", cnt);

    return 0;
}
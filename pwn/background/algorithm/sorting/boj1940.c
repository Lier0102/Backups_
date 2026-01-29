#include <stdio.h>
#include <stdlib.h>

int comp(const void *a, const void *b) {
    return (*(int *)a) - (*(int *)b);
}

int main() {
    int n, m;
    int cnt = 0;
    int left = 0;
    int right;

    scanf("%d %d", &n, &m);

    right = n-1;

    int *a = (int *)malloc(sizeof(int) * n);

    for (int i = 0; i < n; i++) {
        scanf("%d", &a[i]);
    }

    qsort(a, n, sizeof(int), comp);

    while (left < right) {
        int mid = a[left] + a[right];

        if (mid == m) {
            cnt++;
            left++; right--;
        } else if (mid < m) {
            left++;
        } else {
            right--;
        }
    }

    printf("%d\n", cnt);

    return 0;
}
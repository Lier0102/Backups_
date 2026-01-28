#include <stdio.h>
#include <stdlib.h>

int a[100001];

int comp(const void *a, const void *b) {
    return (*(int *)b) - (*(int *)a);
}

int main() {
    int n;
    int max = -1;

    scanf("%d", &n);

    for (int i = 0; i < n; i++) scanf("%d", &a[i]);

    qsort(a, n, sizeof(int), comp);

    for (int i = 1; i <= n; i++) {
        int w = a[i - 1] * i;

        if (w > max) {
            max = w;
        }
    }

    printf("%d\n", max);

    return 0;
}
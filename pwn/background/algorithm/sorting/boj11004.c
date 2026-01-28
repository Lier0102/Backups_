#include <stdio.h>
#include <stdlib.h>

int a[5000001];

int comp(const void *a, const void *b) {
    return (*(int *)a) - (*(int *)b);
}

int main() {
    int n, k;

    scanf("%d %d", &n, &k);

    for (int i = 0; i < n; i++) scanf("%d", &a[i]);

    qsort(a, n, sizeof(int), comp);

    printf("%d\n", a[k-1]);

    return 0;
}
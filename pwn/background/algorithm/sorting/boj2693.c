#include <stdio.h>
#include <stdlib.h>

int comp(const void *a, const void *b) {
    return (*(int *)b)-(*(int *)a);
}

int main() {
    int t; // n
    scanf("%d", &t);

    while(t--) {
        int a[10];
        for (int i = 0; i < 10; i++) {
            scanf("%d", &a[i]);
        }

        qsort(a, 10, sizeof(int), comp);

        printf("%d\n", a[2]);
    }

    return 0;
}
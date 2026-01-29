#include <stdio.h>
#include <stdlib.h>

int a[1000001];
int b[1000001];

// nothing to do here..

int main() {
    int n, m;

    if (scanf("%d %d", &n, &m) == EOF) return 0;

    for (int i = 0; i < n; i++) scanf("%d", &a[i]);
    for (int i = 0; i < m; i++) scanf("%d", &b[i]);

    int i = 0, j = 0;

    while(i < n && j < m) {
        if (a[i] <= b[j]) {
            printf("%d ", a[i++]);
        } else {
            printf("%d ", b[j++]);
        }
    }

    while (i < n) {
        printf("%d ", a[i++]);
    }

    while (j < m) {
        printf("%d ", b[j++]);
    }

    return 0;
}
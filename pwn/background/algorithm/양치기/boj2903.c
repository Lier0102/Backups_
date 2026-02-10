#include <stdio.h>

int main() {
    int n;
    scanf("%d", &n);

    int p = 1; // for the points
    for (int i = 0; i < n; i++) {
        p *= 2;
    }

    p += 1;

    printf("%d\n", p * p);

    return 0;
}
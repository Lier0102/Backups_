#include <stdio.h>
#include <stdlib.h>

int map[2001];

int main() {
    int n;

    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        int v;
        scanf("%d", &v);

        map[v + 1000] = 1;
    }

    for (int i = 0; i <= 2000; i++) {
        if (map[i] == 1) {
            printf("%d ", i - 1000);
        }
    }

    return 0;
}
#include <stdio.h>

int main() {
    int t, n, k, candy;
    scanf("%d", &t);

    while (t--) {
        int res = 0;
        scanf("%d %d", &n, &k);

        for (int i = 0; i < n; i++) {
            scanf("%d", &candy);
            res += (candy / k);
        }
        printf("%d\n", res);
    }

    return 0;
}
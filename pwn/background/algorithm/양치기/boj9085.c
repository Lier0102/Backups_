#include <stdio.h>

int main() {
    int t, n;
    scanf("%d", &t);

    while (t--) {
        int sum = 0;
        scanf("%d", &n);

        for (int i = 0; i < n; i++) {
            int v;
            scanf("%d", &v);
            sum += v;
        }
        printf("%d\n", sum);
    }

    return 0;
}
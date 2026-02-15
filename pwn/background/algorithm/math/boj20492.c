#include <stdio.h>

int main() {
    int n;
    scanf("%d", &n);

    int res1 = n * 0.78;
    int res2 = n - (n * 0.2 * 0.22);
    printf("%d %d", res1, res2);

    return 0;
}
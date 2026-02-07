#include <stdio.h>

int main() {
    while (1) {
        long long a;
        scanf("%lld", &a);

        if (!a) break;

        long long b = a * (a + 1) / 2;

        printf("%lld\n", b);
    }

    return 0;
}
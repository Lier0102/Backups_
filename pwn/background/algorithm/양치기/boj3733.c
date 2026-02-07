#include <stdio.h>

int main() {
    long long n, s;
    while (scanf("%lld %lld", &n, &s) != EOF) {
        printf("%lld\n", s / (n + 1));
    }

    return 0;
}
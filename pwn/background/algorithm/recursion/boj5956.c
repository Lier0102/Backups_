#include <stdio.h>

long long cows(long long n, long long m) {
    if (n % 2 == 0 || m % 2 == 0) {
        return 0;
    }

    return 1 + 4 * cows(n / 2, m / 2);
}

int main() {
    long long n, m;
    scanf("%lld %lld", &n, &m);
    printf("%lld", cows(n, m));

    return 0;
}
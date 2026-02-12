#include <stdio.h>

long long size[6];

int main() {
    long long n, t, p;
    scanf("%lld", &n);

    for (int i = 0; i < 6; i++) {
        scanf("%lld", &size[i]);
    }

    scanf("%lld %lld", &t, &p);

    long long bundle = 0; // bundles, tshirts

    for (int i = 0; i < 6; i++) {
        if (size[i] == 0) continue;

        bundle += (size[i] / t);
        if (size[i] % t != 0) {
            bundle++;
        }
    }

    long long pen = n / p;
    long long pen2 = n % p;

    printf("%lld\n", bundle);
    printf("%lld %lld\n", pen, pen2);

    return 0;
}
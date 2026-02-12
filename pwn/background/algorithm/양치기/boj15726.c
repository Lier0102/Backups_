#include <stdio.h>

int main() {
    double a, b, c;
    scanf("%lf %lf %lf", &a, &b, &c);

    double r1 = (a*b)/c;
    double r2 = (a/b)*c;

    double max = (r1 > r2) ? r1 : r2;

    printf("%lld\n", (long long)max);

    return 0;
}
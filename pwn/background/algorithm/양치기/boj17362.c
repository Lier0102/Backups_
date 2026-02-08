#include <stdio.h>

int main() {
    long long n;
    if (scanf("%lld", &n) != 1) return 0;

    int remainder = n % 8;

    if (remainder == 1) {
        printf("1\n");
    } else if (remainder == 2 || remainder == 0) {
        printf("2\n");
    } else if (remainder == 3 || remainder == 7) {
        printf("3\n");
    } else if (remainder == 4 || remainder == 6) {
        printf("4\n");
    } else if (remainder == 5) {
        printf("5\n");
    }

    return 0;
}
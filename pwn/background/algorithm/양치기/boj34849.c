#include <stdio.h>

int main() {
    long long n;
    scanf("%lld", &n);

    if (n <= 10000) {
        puts("Accepted");
    } else {
        puts("Time limit exceeded");
    }

    return 0;
}
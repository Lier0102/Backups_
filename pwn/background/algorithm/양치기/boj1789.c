#include <stdio.h>

int main() {
    long long s, sum = 0;
    long long i = 1, n = 0;
    scanf("%lld", &s);
    
    while (1) {
        sum += i;
        if (sum > s) break;
        n++; i++;
    }

    printf("%d", n);

    return 0;
}
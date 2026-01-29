#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char n[100001];

int comp(const void *a, const void *b) {
    return *(char *)b - *(char *)a;
}

int main() {
    scanf("%s", n);

    int len = strlen(n); int sum = 0; int flag = 0;

    for (int i = 0; i < len; i++) {
        sum += n[i] - '0';
        if (n[i] == '0') {
            flag = 1;
        }
    }

    if (!flag || sum % 3 != 0) {
        puts("-1"); return 0;
    }

    qsort(n, len, sizeof(char), comp);

    puts(n);

    return 0;
}
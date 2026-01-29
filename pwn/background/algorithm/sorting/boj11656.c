#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char s[1001];
char *suf[1001];

int comp(const void *a, const void *b) {
    return strcmp(*(char **)a, *(char **)b);
}

int main() {
    scanf("%s", s);

    int len = strlen(s);

    for (int i = 0; i < len; i++) {
        suf[i] = &s[i];
    }

    qsort(suf, len, sizeof(char *), comp);

    for (int i = 0; i < len; i++) {
        printf("%s\n", suf[i]);
    }

    return 0;
}
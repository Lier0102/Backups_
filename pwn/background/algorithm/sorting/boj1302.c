#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char book[1001][51];

int comp(const void *a, const void *b) {
    return strcmp((char *)a, (char *)b); // shouldn't be ref
}

int main() {
    int n;
    char best[51];
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        scanf("%s", book[i]);
    }

    qsort(book, n, sizeof(book[0]), comp);

    strcpy(best, book[0]);

    int max = 1;
    int cnt = 1;

    for (int i = 1; i < n; i++) {
        if (strcmp(book[i], book[i - 1]) == 0) {
            cnt++;
        } else {
            cnt = 1;
        }

        if (cnt > max) {
            max = cnt;
            strcpy(best, book[i]);
        }
    }

    printf("%s", best);

    return 0;
}
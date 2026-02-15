#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char name[6];
    char stat[6];
} log;

int comp(const void *a, const void *b) {
    log *l1 = (log *)a;
    log *l2 = (log *)b;

    return strcmp(l1->name, l2->name);
}

log l[1000001];

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) scanf("%s %s", l[i].name, l[i].stat);

    qsort(l, n, sizeof(log), comp);

    for (int i = n - 1; i >= 0; i--) {
        if (i > 0 && strcmp(l[i].name, l[i-1].name) == 0) {
            i--; continue;
        }

        if (strcmp(l[i].stat, "enter") == 0) {
            puts(l[i].name);
        }
    }

    return 0;
}
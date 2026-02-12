#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char name[21];
    int id;
} Poke;

int comp(const void *a, const void *b) {
    return strcmp(((Poke *)a)->name, ((Poke *)b)->name);
}

Poke a[100001];
Poke sa[100001]; //sorted

int main() {
    int n, m;
    scanf("%d %d", &n, &m);

    for (int i = 1; i <= n; i++) {
        scanf("%s", a[i].name);
        a[i].id = i;
        sa[i] = a[i];
    }

    qsort(sa + 1, n, sizeof(Poke), comp); // starts with idx of 1 lol

    char tmp[21];
    while (m--) {
        scanf("%s", tmp);

        if (isdigit(tmp[0])) {
            int v = atoi(tmp);
            printf("%s\n", a[v].name);
        } else {
            int low = 1, high = n;
            while (low <= high) {
                int mid = (low + high) / 2;
                int res = strcmp(sa[mid].name, tmp);

                if (!res) {
                    printf("%d\n", sa[mid].id);
                    break;
                } else if (res < 0) {
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }
        }
    }

    return 0;
}
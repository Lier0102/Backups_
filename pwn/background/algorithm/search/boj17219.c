#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char site[21];
    char pw[21];
} Memo;

int comp(const void *a, const void *b) {
    return strcmp(((Memo *)a)->site, ((Memo *)b)->site);
}

Memo a[100001];

int main() {
    int n, m;
    scanf("%d %d", &n, &m);

    for (int i = 0; i < n; i++) {
        scanf("%s %s", a[i].site, a[i].pw);
    }

    qsort(a, n, sizeof(Memo), comp);

    char tmp[21];
    for (int i = 0; i < m; i++) {
        scanf("%s", tmp);

        int low = 0, high = n - 1;
        while (low <= high) {
            int mid = (low + high) / 2;
            int res = strcmp(a[mid].site, tmp);

            if (!res) {
                printf("%s\n", a[mid].pw);
                break;
            } else if (res < 0) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
    }

    return 0;
}
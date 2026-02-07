#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int l, h;
} P; // pillar

P p[1001];

int comp(const void *a, const void *b) {
    return ((P *)a)->l - ((P *)b)->l;
}

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        scanf("%d %d", &p[i].l, &p[i].h);
    }

    int mh=0, mi=0; // max height, max l(<< l is not for index tho)

    qsort(p, n, sizeof(P), comp);

    for (int i = 0; i < n; i++) {
        if (p[i].h > mh) {
            mh = p[i].h;
            mi = i;
        }
    }

    int area = 0;

    int cur = 0;
    for (int i = 0; i <= mi; i++) {
        if (p[i].h > cur) cur = p[i].h;

        if (i < mi) {
            area += cur * (p[i+1].l - p[i].l);
        }
    }

    cur = 0;
    for (int i = n - 1; i > mi; i--) {
        if (p[i].h > cur) cur = p[i].h;

        area += cur * (p[i].l - p[i-1].l);
    }

    area += mh;

    printf("%d", area);

    return 0;
}
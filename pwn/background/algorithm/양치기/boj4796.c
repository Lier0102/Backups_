#include <stdio.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

int main() {
    int l, p, v;
    int i = 1;

    while (1) {
        scanf("%d %d %d", &l, &p, &v);

        if (!l && !p && !v) break;
        int set = (v / p) * l;
        int r = MIN(v % p, l); // r : rest

        int res = set + r;

        printf("Case %d: %d\n", i++, res);
    }

    return 0;
}
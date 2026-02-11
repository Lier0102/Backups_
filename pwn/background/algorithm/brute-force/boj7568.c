#include <stdio.h>

typedef struct {
    int w;
    int h;
} P;

P p[50];

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        scanf("%d %d", &p[i].w, &p[i].h);
    }

    for (int i = 0; i < n; i++) {
        int rank = 1;
        for (int j = 0; j < n; j++) {
            if (i == j) continue;

            if (p[j].w > p[i].w && p[j].h > p[i].h) {
                rank++;
            }
        }
        printf("%d ", rank);
    }

    return 0;
}
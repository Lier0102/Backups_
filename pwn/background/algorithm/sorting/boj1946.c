#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int doc;
    int inter;
} App;

int comp(const void *a, const void *b) {
    App *a1 = (App *)a;
    App *a2 = (App *)b;

    return a1->doc - a2->doc;
}

int main(void) {
    int t;

    scanf("%d", &t);

    // for(int i = 0; i < t; i++) {

    // }

    while(t--) {
        int n;
        App app[100001];

        scanf("%d", &n);

        for (int i = 0; i < n; i++) {
            scanf("%d %d", &app[i].doc, &app[i].inter);
        }

        qsort(app, n, sizeof(App), comp);

        int cnt = 1; // 최소 한 명
        int min = app[0].inter;

        for (int i = 1; i < n; i++) {
            if (app[i].inter < min) {
                min = app[i].inter;
                cnt++;
            }
        }
        printf("%d\n", cnt);
    }

    return 0;
}
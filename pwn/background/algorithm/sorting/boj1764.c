#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char nh[500001][21]; // not heard
char ns[500001][21];
char res[500001][21];

int comp(const void *a, const void *b) {
    return strcmp((char *)a, (char *)b);
}

int main(void) {
    int n, m;
    
    int cnt = 0;

    scanf("%d %d", &n, &m);

    for (int i = 0; i < n; i++) {
        scanf("%s", nh[i]);
    }

    for (int i = 0; i < m; i++) {
        scanf("%s", ns[i]);
    }

    qsort(nh, n, sizeof(nh[0]), comp);
    qsort(ns, m, sizeof(nh[0]), comp);

    int i = 0, j = 0;

    while (i < n && j < m) {
        int cmp = strcmp(nh[i], ns[j]);

        if (cmp == 0) {
            strcpy(res[cnt++], nh[i]);
            i++; j++;
        } else if (cmp < 0) { // cmp == -1?
            i++;
        } else {
            j++;
        }
    }

    printf("%d\n", cnt);
    for (int i = 0; i < cnt; i++) {
        printf("%s\n", res[i]);
    }

    return 0;
}

// REF: https://hand-over.tistory.com/26
// 작다? -> 사전순으로 앞선다 ㅇㅇ
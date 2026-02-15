#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char s[10001][501];
char target[501];

int comp(const void *a, const void *b) {
    return strcmp((char *)a, (char *)b);
}

int search(char *target, int n) {
    int low = 0, high = n - 1;

    while (low <= high) {
        int mid = (low + high) / 2;
        int res = strcmp(s[mid], target);

        if (res == 0) {
            return 1;
        } else if (res < 0) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    return 0;
}

int main() {
    int n, m;
    scanf("%d %d", &n, &m);

    for (int i = 0; i < n; i++) {
        scanf("%s", s[i]);
    }

    qsort(s, n, sizeof(s[0]), comp); // size of char, s[0]

    int cnt = 0;
    for (int i = 0; i < m; i++) {
        scanf("%s", target);

        if (search(target, n)) {
            cnt++;
        }
    }

    printf("%d", cnt);

    return 0;
}
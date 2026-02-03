#include <stdio.h>

int a[100001];
int b[100001];
int res[200001];

int main() {
    int n, m;

    scanf("%d", &n);

    for (int i = 0; i < n; i++) scanf("%d", &a[i]);
    for (int i = 0; i < n; i++) scanf("%d", &b[i]);

    int idx = 0;

    for (int i = n - 1; i >= 0; i--) {
        if (a[i] == 0) {
            res[idx++] = b[i];
        }
    }

    scanf("%d", &m);

    for (int i = 0; i < m; i++) {
        int x;
        scanf("%d", &x);

        res[idx++] = x;

        printf("%d ", res[i]);
    }

    return 0;
}
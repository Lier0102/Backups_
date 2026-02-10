#include <stdio.h>

int n, m;
char map[51][51];

int solve(int r, int c) {
    int cnt = 0; // cnt for the wrong W

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            if ((i + j) % 2 == 0) {
                if (map[r + i][c + j] != 'W') cnt++;
            } else {
                if (map[r + i][c + j] != 'B') cnt++;
            }
        }
    }

    return (cnt < (64 - cnt) ? cnt : (64 - cnt));
}

int main() {
    int min = 64;
    scanf("%d %d", &n, &m);

    for (int i = 0; i < n; i++) {
        scanf("%s", map[i]);
    }

    for (int i = 0; i <= n - 8; i++) {
        for (int j = 0; j <= m - 8; j++) {
            int tmp = solve(i, j);
            if (tmp < min) {
                min = tmp;
            }
        }
    }

    printf("%d", min);

    return 0;
}
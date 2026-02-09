#include <stdio.h>

int map[65][65]; // 1 to 64

void solve(int r, int c, int size) {
    int cur = map[r][c];
    int flag = 1;

    for (int i = r; i < r + size; i++) {
        for (int j = c; j < c + size; j++) {
            if (map[i][j] != cur) {
                flag = 0;
                break;
            }
        }
        if (!flag) break;
    }

    if (flag) {
        printf("%d", cur);
        return;
    }

    printf("(");
    int next = size / 2;

    solve(r, c, next);
    solve(r, c + next, next);
    solve(r + next, c, next);
    solve(r + next, c + next, next);

    printf(")");
}

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            scanf("%1d", &map[i][j]); // one by one
        }
    }

    solve(0, 0, n);

    return 0;
}
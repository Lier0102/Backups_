#include <stdio.h>

// 4 * (n - 1) + 1
char map[401][401];

void recur(int n, int r, int c) {
    if (n == 1) {
        map[r][c] = '*';
        return ;
    }

    int len = 4 * (n - 1) + 1;

    for (int i = 0; i < len; i++) {
        map[r][c + i] = '*';
        map[r + len - 1][c + i] = '*';
        map[r + i][c] = '*';
        map[r + i][c + len - 1] = '*';
    }

    recur(n - 1, r + 2, c + 2);
}

int main() {
    int n;
    scanf("%d", &n);

    int len = 4 *(n - 1) + 1;
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < len; j++) {
            map[i][j] = ' ';
        }
    }

    recur(n, 0, 0);

    for (int i = 0; i < len; i++) {
        for (int j = 0; j < len; j++) {
           printf("%c", map[i][j]);
        }
        puts("");
    }

    return 0;
}
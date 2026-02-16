#include <stdio.h>

int n, m;
char map[601][601];
int visited[601][601]; // can use 'char' to optimization maybe
int res; // bss section

int dx[] = {1, -1, 0, 0};
int dy[] = {0, 0, 1, -1};

void dfs(int x, int y) {
    visited[x][y] = 1;

    if (map[x][y] == 'P') {
        res++;
    }

    for (int i = 0; i < 4; i++) {
        int nx = x + dx[i];
        int ny = y + dy[i];

        if (nx >= 0 && nx < n && ny >= 0 && ny < m) {
            if (map[nx][ny] != 'X' && !visited[nx][ny]) {
                dfs(nx, ny);
            }
        }
    }
}

int main() {
    int startX, startY;
    scanf("%d %d", &n, &m);

    for (int i = 0; i < n; i++) {
        scanf("%s", map[i]);

        for (int j = 0; j < m; j++) {
            if (map[i][j] == 'I') {
                startX = i;
                startY = j; // actually x = y, y = x here.. kinda reversed
            }
        }
    }

    dfs(startX, startY);

    if (!res) {
        puts("TT");
    } else {
        printf("%d", res);
    }

    return 0;
}
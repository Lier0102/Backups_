#include <stdio.h>

int r, c;
char map[101][101];

int dy[] = {-1, 1, 0, 0};
int dx[] = {0, 0, -1, 1};

void dfs(int y, int x) {
    map[y][x] = '.';

    for (int i = 0; i < 4; i++) {
        int ny = y + dy[i];
        int nx = x + dx[i];

        if (ny >= 0 && ny < r && nx >= 0 && nx < c) {
            if (map[ny][nx] == '#') {
                dfs(ny, nx);
            }
        }
    }
}

int main() {
    scanf("%d %d", &r, &c);
    for (int i = 0; i < r; i++) {
        scanf("%s", map[i]);
    }

    int cnt = 0;
    for (int i = 0; i < r; i++) {
        for (int j = 0; j < c; j++) {
            if (map[i][j] == '#') {
                cnt++;
                dfs(i, j);
            }
        }
    }

    printf("%d", cnt);

    return 0;
}
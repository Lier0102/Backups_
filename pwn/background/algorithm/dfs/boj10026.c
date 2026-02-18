#include <stdio.h>
#include <string.h>

int n;
char map[101][101];
int visited[101][101];

int dx[] = {1, -1, 0, 0};
int dy[] = {0, 0, -1, 1};

void dfs(int x, int y, char c) {
    visited[x][y] = 1;

    for (int i = 0; i < 4; i++) {
        int nx = x + dx[i];
        int ny = y + dy[i];

        if (nx >= 0 && nx < n && ny >= 0 && ny < n) {
            if (!visited[nx][ny] && map[nx][ny] == c) {
                dfs(nx, ny, c);
            }
        }
    }
}

int count() {
    int cnt = 0;
    memset(visited, 0, sizeof(visited));

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (!visited[i][j]) {
                dfs(i, j, map[i][j]);
                cnt++;
            }
        }
    }

    return cnt;
}

int main() {
    scanf("%d", &n);
    for (int i = 0; i < n; i++) {
        scanf("%s", map[i]);
    }

    int res1 = count();

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (map[i][j] == 'G') map[i][j] = 'R';
        }
    }

    int res2 = count();

    printf("%d %d", res1, res2);

    return 0;
}
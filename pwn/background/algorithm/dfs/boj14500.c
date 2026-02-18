#include <stdio.h>

int n, m, res;
int map[500][500];
int visited[500][500];
int dy[] = {0, 0, 1, -1};
int dx[] = {1, -1, 0, 0};

void dfs(int y, int x, int sum, int depth) {
    if (depth == 4) {
        if (sum > res) res = sum;
        return;
    }

    for (int i = 0; i < 4; i++) {
        int ny = y + dy[i];
        int nx = x + dx[i];

        if (ny < 0 || ny >= n || nx < 0 || nx >= m) continue;
        if (!visited[ny][nx]) {
            visited[ny][nx] = 1;
            dfs(ny, nx, sum + map[ny][nx], depth + 1);
            visited[ny][nx] = 0;
        }
    }
}

void check_ex(int y, int x) {
    for (int i = 0; i < 4; i++) {
        int sum = map[y][x];
        int possible = 1;
        for (int j = 0; j < 3; j++) {
            int cur = (i + j) % 4;
            int ny = y + dy[cur];
            int nx = x + dx[cur];

            if (ny < 0 || ny >= n || nx < 0 || nx >= m) {
                possible = 0;
                break;
            }
            sum += map[ny][nx];
        }
        if (possible && sum > res) res = sum;
    }
}

int main() {
    scanf("%d %d", &n, &m);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            scanf("%d", &map[i][j]);
        }
    }

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            visited[i][j] = 1;
            dfs(i, j, map[i][j], 1);
            visited[i][j] = 0;
            check_ex(i, j);
        }
    }

    printf("%d\n", res);
    return 0;
}
#include <stdio.h>
#include <string.h>

int m, n, k;
int dx[] = {0, 0, -1, 1}; // up-down-left-right
int dy[] = {-1, 1, 0, 0};
int arr[51][51];
int visited[51][51];

void dfs(int x, int y) {
    visited[x][y] = 1;
    for (int i = 0; i < 4; i++) {
        int nx = x + dx[i];
        int ny = y + dy[i];

        if (nx >= 0 && nx < m && ny >= 0 && ny < n) {
            if (arr[nx][ny] == 1 && !visited[nx][ny]) {
                dfs(nx, ny);
            }
        }
    }
}

int main() {
    int t;
    scanf("%d", &t);

    while (t--) {
        scanf("%d %d %d", &m, &n, &k);

        memset(arr, 0, sizeof(arr));
        memset(visited, 0, sizeof(visited));

        for (int i = 0; i < k; i++) {
            int x, y;
            scanf("%d %d", &x, &y);
            arr[x][y] = 1;
        }

        int cnt = 0;
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < n; j++) {
                if (arr[i][j] == 1 && !visited[i][j]) {
                    cnt++;
                    dfs(i, j);
                }
            }
        }
        printf("%d\n", cnt);
    }

    return 0;
}
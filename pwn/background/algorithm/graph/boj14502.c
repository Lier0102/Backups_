#include <stdio.h>
#include <string.h>

int n, m, max;
int dy[] = {0, 0, 1, -1};
int dx[] = {1, -1, 0, 0};
int map[8][8], tmp[8][8];

void bfs() {
    int res[8][8]; // map after infections
    memcpy(res, tmp, sizeof(tmp));

    int q[64][2], front = 0, rear = 0;

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            if (res[i][j] == 2) {
                q[rear][0] = i;
                q[rear][1] = j;
                rear++;
            }
        }
    }

    while (front < rear) {
        int y = q[front][0], x = q[front][1]; front++;

        for (int i = 0; i < 4; i++) {
            int nx = x + dx[i];
            int ny = y + dy[i];

            if (ny >= 0 && ny < n && nx >= 0 && nx < m && !res[ny][nx]) {
                res[ny][nx] = 2;
                q[rear][0] = ny;
                q[rear++][1] = nx;
            }
        }
    }

    int cnt = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < m; j++) if (!res[i][j]) cnt++;

    if (cnt > max) max = cnt;
}

void wall(int cnt) {
    if (cnt == 3) {
        bfs();
        return;
    }
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            if (!tmp[i][j]) {
                tmp[i][j] = 1;
                wall(cnt + 1);
                tmp[i][j] = 0;
            }
        }
    }
}

int main() {
    scanf("%d %d", &n, &m);

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            scanf("%d", &map[i][j]);
        }
    }

    memcpy(tmp, map, sizeof(map));
    wall(0);
    printf("%d", max);
    
    return 0;
}
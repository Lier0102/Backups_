#include <stdio.h>

typedef struct {
    int x, y;
} Node;

int n, m;
int map[1001][1001];
int visited[1001][1001];
Node q[1000001];
int front, rear;

int dx[] = {0, 0, -1, 1};
int dy[] = {-1, 1, 0, 0};

void bfs(int x, int y) {
    front = 0, rear = 0;
    q[rear++] = (Node){x, y};
    visited[x][y] = 0;

    while (front < rear) {
        Node cur = q[front++]; //pop

        for (int i = 0; i < 4; i++) {
            int nx = cur.x + dx[i];
            int ny = cur.y + dy[i];

            if (nx < 0 || nx >= n || ny < 0 || ny >= m) continue;

            if (map[nx][ny] == 1 && visited[nx][ny] == -1) {
                visited[nx][ny] = visited[cur.x][cur.y] + 1;
                q[rear++] = (Node){nx, ny};
            }
        }
    }
}

int main() {
    int x, y;
    scanf("%d %d", &n, &m);

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            scanf("%d", &map[i][j]);

            if (map[i][j] == 2) {
                x = i; y = j;
                visited[i][j] = 0;
            } else if (!map[i][j]) {
                visited[i][j] = 0;
            } else {
                visited[i][j] = -1; // can be visited
            }
        }
    }

    bfs(x, y);

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            printf("%d ", visited[i][j]);
        }
        puts("");
    }

    return 0;
}
#include <stdio.h>

#define MAX 1000001

typedef struct {
    int x, y;
} Node;

int m, n;
int map[1001][1001];
Node q[MAX];
int front = 0, rear = 0;

int dx[] = {0, 0, -1, 1};
int dy[] = {-1, 1, 0, 0};

int main() {
    scanf("%d %d", &m, &n);

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            scanf("%d", &map[i][j]);

            if (map[i][j] == 1) {
                q[rear].x = i;
                q[rear].y = j;
                rear++;
            }
        }
    }

    while (front < rear) {
        Node cur = q[front++];

        for (int i = 0; i < 4; i++) {
            int nx = cur.x + dx[i];
            int ny = cur.y + dy[i];

            if (nx >= 0 && nx < n && ny >= 0 && ny < m) {
                if (!map[nx][ny]) {
                    map[nx][ny] = map[cur.x][cur.y] + 1;
                    q[rear].x = nx;
                    q[rear].y = ny;
                    rear++;
                }
            }
        }
    }

    int max = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            if (!map[i][j]) {
                puts("-1");
                return 0;
            }
            if (map[i][j] > max) {
                max = map[i][j];
            }
        }
    }

    if (!max) puts("0");
    else printf("%d", max - 1);

    return 0;
}
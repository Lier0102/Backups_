#include <stdio.h>

typedef struct {
    int z, y, x;
} Node;

int n, m, h;
int box[101][101][101];
Node q[1000001];

int dz[] = {1, -1, 0, 0, 0, 0};
int dy[] = {0, 0, 1, -1, 0, 0};
int dx[] = {0, 0, 0, 0, 1, -1};

int front, rear;

int main() {
    scanf("%d %d %d", &m, &n, &h);

    int res = 0;

    for (int i = 0; i < h; i++) {
        for (int j = 0; j < n; j++) {
            for (int k = 0; k < m; k++) {
                scanf("%d", &box[i][j][k]);
                if (box[i][j][k] == 1) {
                    q[rear++] = (Node){i, j, k};
                } else if (!box[i][j][k]) {
                    res++;
                }
            }
        }
    }

    if (!res) {
        puts("0");
        return 0;
    }

    int d = 0; // for the days
    while (front < rear) {
        int size = rear - front;
        int moved = 0; // for the moved

        for (int i = 0; i < size; i++) {
            Node cur = q[front++];

            for (int d = 0; d < 6; d++) {
                int nz = cur.z + dz[d];
                int ny = cur.y + dy[d];
                int nx = cur.x + dx[d];
                
                if (nz >= 0 && nz < h && ny >= 0 && ny < n && nx >= 0 && nx < m) {
                    if (!box[nz][ny][nx]) {
                        box[nz][ny][nx] = 1;
                        q[rear++] = (Node){nz, ny, nx};
                        res--;
                        moved = 1;
                    }
                }
            }
        }
        if (moved) d++;
    }

    if (res > 0) puts("-1");
    else printf("%d", d);

    return 0;
}
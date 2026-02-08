#include <stdio.h>

int n, k, l;
int map[101][101];

typedef struct {
    int sec;
    char dir;
} Turn;

Turn t[101];
int queue_r[10101], queue_c[10101];
int dr[] = {-1, 0, 1, 0};
int dc[] = {0, 1, 0, -1};
int front = 0, rear = 0;

void solve() {
    int r = 1, c = 1, d = 1, time = 0, idx = 0; // idx = turn idx;
    map[r][c] = 2;

    queue_r[rear] = r; queue_c[rear++] = c;

    while (1) {
        time++;
        int nr = r + dr[d];
        int nc = c + dc[d];

        if (nr < 1 || nr > n || nc < 1 || nc > n || map[nr][nc] == 2) break;

        if (map[nr][nc] == 1) {
            map[nr][nc] = 2;
            queue_r[rear] = nr; queue_c[rear++] = nc;
        } else { // non-apple
            map[nr][nc] = 2;
            queue_r[rear] = nr; queue_c[rear++] = nc;

            int tr = queue_r[front];
            int tc = queue_c[front++];

            map[tr][tc] = 0;
        }

        r = nr; c = nc;

        if (idx < l && t[idx].sec == time) {
            if (t[idx].dir == 'D') d = (d + 1) % 4;
            else d = (d + 3) % 4;
            idx++;
        }
    }

    printf("%d\n", time);
}

int main() {
    scanf("%d %d", &n, &k);
    for (int i = 0; i < k; i++) {
        int r, c;
        scanf("%d %d", &r, &c);

        map[r][c] = 1;
    }

    scanf("%d", &l);

    for (int i = 0; i < l; i++) {
        scanf("%d %c", &t[i].sec, &t[i].dir);
    }

    solve();

    return 0;
}
#include <stdio.h>

int n, m;
int r[101];
int w[2001];
int queue[2001]; // queue for waiting
int space[101] = {0}; // for the parked
long long res;
int front, rear;

void solve() {
    front = 0, rear = 0;
    for (int i = 0; i < 2 * m; i++) {
        int c;
        scanf("%d", &c); // c for car;

        if (c > 0) {
            int flag = 0;

            for (int j = 1; j <= n; j++) {
                if (!space[j]) {
                    space[j] = c;
                    res += (long long)w[c] * r[j];
                    flag = 1;
                    break;
                }
            }

            if (!flag) {
                queue[rear++] = c;
            }
        } else {
            int tmp = -c;
            int tmp_space = 0;

            for (int j = 1; j <= n; j++) {
                if (space[j] == tmp) {
                    space[j] = 0;
                    tmp_space = j;
                    break;
                }
            }

            if (front < rear) {
                int nc = queue[front++]; // next car
                space[tmp_space] = nc;
                res += (long long)w[nc] * r[tmp_space];
            }
        }
    }
}

int main() {
    scanf("%d %d", &n, &m);

    for (int i = 1; i <= n; i++) scanf("%d", &r[i]);
    for (int i = 1; i <= m; i++) scanf("%d", &w[i]);

    solve();

    printf("%lld\n", res);
}
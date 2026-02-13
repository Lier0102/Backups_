#include <stdio.h>
#define INF 1000001

int main() {
    int n, m;
    int visited[101][101];

    scanf("%d %d", &n, &m);

    for (int i = 1; i <= n; i++) {
        for (int j = 1; j <= n; j++) {
            if (i == j) visited[i][j] = 0;
            else visited[i][j] = INF;
        }
    }

    for (int i = 0; i < m; i++) {
        int u, v;
        scanf("%d %d", &u, &v);
        visited[u][v] = 1;
        visited[v][u] = 1;
    }

    for (int k = 1; k <= n; k++) {
        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= n; j++) {
                if (visited[i][j] > visited[i][k] + visited[k][j]) {
                    visited[i][j] = visited[i][k] + visited[k][j];
                }
            }
        }
    }

    int min = INF;
    int res = 0;

    for (int i = 1; i <= n; i++) {
        int sum = 0;
        for (int j = 1; j <= n; j++) {
            sum += visited[i][j];
        }

        if (sum < min) {
            min = sum;
            res = i;
        }
    }

    printf("%d", res);

    return 0;
}
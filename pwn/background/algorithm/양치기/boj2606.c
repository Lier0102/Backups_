#include <stdio.h>

int graph[101][101];
int visited[101];
int queue[101];
int front = 0, rear = 0;

int main() {
    int n, m;
    scanf("%d%d", &n, &m);

    for (int i = 0; i < m; i++) {
        int u, v;
        scanf("%d %d", &u, &v);
        graph[u][v] = graph[v][u] = 1;
    }

    queue[rear++] = 1;
    visited[1] = 1;
    int cnt = 0;

    while (front < rear) {
        int cur = queue[front++];

        for (int i = 1; i <= n; i++) {
            if (graph[cur][i] == 1 && !visited[i]) {
                visited[i] = 1;
                queue[rear++] = i;
                cnt++;
            }
        }
    }

    printf("%d\n", cnt);
}
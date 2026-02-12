#include <stdio.h>

int n, m;
int arr[1001][1001];
int visited[1001];

void dfs(int u) {
    visited[u] = 1;

    for (int v = 1; v <= n; v++) {
        if (arr[u][v] && !visited[v]) {
            dfs(v);
        }
    }
}

int main() {
    scanf("%d %d", &n, &m);

    for (int i = 0; i < m; i++) {
        int u, v;
        scanf("%d %d", &u, &v);

        arr[u][v] = 1;
        arr[v][u] = 1;
    }

    int cnt = 0;
    for (int i = 1; i <= n; i++) {
        if (!visited[i]) {
            cnt++;
            dfs(i);
        }
    }
    
    printf("%d", cnt);
}
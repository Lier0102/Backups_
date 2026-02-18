#include <stdio.h>
#include <string.h>

typedef struct {
    int num;
    char path[101];
} node;

int visited[10001];
int parent[10001];
char command[10001];
int q[10001];

void bfs(int start, int target) {
    int front = 0, rear = 0;
    memset(visited, 0, sizeof(visited));

    q[rear++] = start;
    visited[start] = 1;

    while (front < rear) {
        int cur = q[front++];

        if (cur == target) return;

        int next[4] = {
            (cur * 2) % 10000,
            (cur == 0) ? 9999 : cur - 1,
            (cur % 1000) * 10 + cur / 1000,
            (cur % 10) * 1000 + cur / 10
        };
        char cmd[4] = {'D', 'S', 'L', 'R'};

        for (int i = 0; i < 4; i++) {
            if (!visited[next[i]]) {
                visited[next[i]] = 1;
                parent[next[i]] = cur;
                command[next[i]] = cmd[i];
                q[rear++] = next[i];
            }
        }
    }
}

void print_path(int start, int target) {
    if (start == target) return;
    print_path(start, parent[target]);
    printf("%c", command[target]);
}

int main() {
    int t, a, b;
    scanf("%d", &t);

    while (t--) {
        scanf("%d %d", &a, &b);

        bfs(a, b);
        print_path(a, b);
        puts("");
    }

    return 0;
}
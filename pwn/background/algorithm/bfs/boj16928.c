#include <stdio.h>

int map[101];
int visited[101];
int queue[101];
int front, rear;

void push(int v) { queue[rear++] = v; }
int pop() { return queue[front++]; }

int main() {
    int n, m, x, y;

    scanf("%d %d", &n, &m);

    for (int i = 1; i <= 100; i++) map[i] = i;

    for (int i = 0; i < n + m; i++) {
        scanf("%d %d", &x, &y);
        map[x] = y;
    }

    push(1);
    visited[1] = 1;

    while (front < rear) {
        int cur = pop();

        if (cur == 100) {
            printf("%d", visited[100] - 1);
            break;
        }

        for (int i = 1; i <= 6; i++) {
            int next = cur + i;
            if (next > 100) continue;

            next = map[next];
            
            if (!visited[next]) {
                visited[next] = visited[cur] + 1;
                push(next);
            }
        }
    }

    return 0;
}
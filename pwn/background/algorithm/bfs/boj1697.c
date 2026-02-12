#include <stdio.h>

int visited[100001];
int queue[100001];
int front = 0, rear = 0;

void push(int v) {
    queue[rear++] = v;
}

int pop() {
    return queue[front++];
}

int main() {
    int n, k;
    scanf("%d %d", &n, &k);

    if (n == k) {
        puts("0");
        return 0;
    }

    push(n);
    visited[n] = 1;

    while (front < rear) {
        int x = pop();

        int next[3] = {x-1, x+1, 2*x};
        for (int i = 0; i < 3; i++) {
            int nx = next[i];

            if (nx >= 0 && nx < 100001 && !visited[nx]) {
                visited[nx] = visited[x] + 1;
                push(nx);

                if (nx == k) {
                    printf("%d\n", visited[nx] - 1);
                    return 0;
                }
            }
        }
    }
    
    return 0;
}
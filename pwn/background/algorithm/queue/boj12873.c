#include <stdio.h>

int queue[5001];
int front = 0, rear = 0;

void push(int v) {
    queue[rear] = v;
    rear = (rear + 1) % 5001;
}

int pop() {
    int v = queue[front];
    front = (front + 1) % 5001;
    return v;
}

int size() {
    return (rear - front + 5001) % 5001;
}

int main() {
    int n;
    scanf("%d", &n);

    for (int i = 1; i <= n; i++) {
        push(i);
    }

    for (long long t = 1; t < n; t++) {
        long long move = t * t * t;
        int cur = size();

        int m = (int)((move - 1) % cur);

        for (int i = 0; i < m; i++) {
            push(pop());
        }

        pop();
    }

    printf("%d\n", queue[front]);

    return 0;
}
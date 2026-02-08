#include <stdio.h>

int main() {
    int n;
    scanf("%d", &n);

    int queue[100001];
    int front = 0, rear = 0;
    int cur_size = 0;

    while (1) {
        int v;
        scanf("%d", &v);

        if (v == -1) break;

        if (!v) {
            front = (front + 1) % (n + 1);
            cur_size--;
        } else {
            if (cur_size < n) {
                queue[rear] = v;
                rear = (rear + 1) % (n + 1);
                cur_size++;
            }
        }
    }

    if (!cur_size) {
        puts("empty");
    } else {
        while (cur_size > 0) {
            printf("%d ", queue[front]);
            front = (front + 1) % (n + 1);
            cur_size--;
        }
        puts("");
    }

    return 0;
}
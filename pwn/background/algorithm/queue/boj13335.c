#include <stdio.h>

int main() {
    int n, w, l;
    int truck[1001];
    int bridge[101] = {0,};

    scanf("%d %d %d", &n, &w, &l);

    for (int i = 0; i < n; i++) {
        scanf("%d", &truck[i]);
    }

    int time = 0;
    int cur_w = 0;
    int idx = 0;
    int front = 0;

    int queue[101];
    int b_front = 0, b_rear = 0;

    for (int i = 0; i < w; i++) {
        queue[b_rear++] = 0;
    }

    while (idx < n) {
        time++;

        cur_w -= queue[b_front];
        b_front = (b_front + 1) % 101; // circular

        if (cur_w + truck[idx] <= l) {
            queue[b_rear] = truck[idx];
            cur_w += truck[idx];
            idx++;
        } else {
            queue[b_rear] = 0;
        }
        b_rear = (b_rear + 1) % 101;
    }

    printf("%d\n", time + w);
}
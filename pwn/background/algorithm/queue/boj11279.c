#include <stdio.h>

int heap[100001];
int size = 0;

void push(int x) {
    heap[++size] = x;
    int child = size;
    int parent = child / 2;

    while (child > 1 && heap[parent] < heap[child]) {
        int tmp = heap[child];
        heap[child] = heap[parent];
        heap[parent] = tmp;

        child = parent;
        parent = child / 2;
    }
}

int pop() {
    if (!size) return 0;

    int res = heap[1];
    heap[1] = heap[size--];

    int parent = 1;
    int child = parent * 2;

    while (child <= size) {
        if (child + 1 <= size && heap[child] < heap[child + 1]) {
            child++;
        }

        if (heap[parent] >= heap[child]) break;

        int tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;

        parent = child;
        child = parent * 2;
    }

    return res;
}

int main() {
    int n, x;
    scanf("%d", &n);

    while (n--) {
        scanf("%d", &x);
        if (x == 0) {
            printf("%d\n", pop());
        } else {
            push(x);
        }
    }

    return 0;
}
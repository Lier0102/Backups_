#include <stdio.h>
#include <stdlib.h>

int heap[1000001];
int size;

// standard: a
int prior(int a, int b) {
    int t1 = abs(a);
    int t2 = abs(b);

    if (t1 < t2) return 1;
    if (t1 == t2 && a < b) return 1;
    
    return 0;
}

void push(int x) {
    heap[++size] = x;
    int child = size;
    int parent = child / 2;

    while (child > 1 && prior(heap[child], heap[parent])) {
        int tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;

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
        if (child + 1 <= size && prior(heap[child + 1], heap[child])) {
            child++;
        }

        if (prior(heap[parent], heap[child])) break;

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
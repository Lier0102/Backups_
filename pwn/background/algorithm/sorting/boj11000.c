#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int start;
    int end;
} class;

int comp(const void *a, const void *b) {
    class *c1 = (class *)a;
    class *c2 = (class *)b;

    if (c1->start == c2->start) return c1->end - c2->end;
    return c1->start-c2->start;
}

int heap[200001];
int size = 0;

void push(int val) {
    heap[++size] = val;
    int child = size;
    int parent = child / 2;

    while (child > 1 && heap[parent] > heap[child]) {
        int tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;

        child = parent;
        parent = child / 2;
    }
}

// int pop
void pop() {
    heap[1] = heap[size--];

    int parent = 1;
    int child = 2;

    while (child <= size) {
        if (child + 1 <= size && heap[child] > heap[child + 1]) child++;
        if (heap[parent] <= heap[child]) break;

        int tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;

        parent = child;
        child = parent * 2;
    }
}

int main() {
    int n;
    scanf("%d", &n);

    class *c = (class *)malloc(sizeof(class) * n);

    for (int i = 0; i < n; i++) {
        scanf("%d %d", &c[i].start, &c[i].end);
    }

    qsort(c, n, sizeof(class), comp);

    push(c[0].end);

    for (int i = 1; i < n; i++) {
        if (heap[1] <= c[i].start) {
            pop();
        }
        push(c[i].end);
    }

    printf("%d\n", size);

    free(c);
    return 0;
}
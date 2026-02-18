#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int v;
    int id;
} node;

node max_heap[1000001];
node min_heap[1000001];
int is_deleted[1000001];

int max_size, min_size;

void push_max(int v, int id) {
    max_heap[++max_size] = (node){v, id};

    int cur = max_size;

    while (cur > 1 && max_heap[cur].v > max_heap[cur/2].v) {
        node tmp = max_heap[cur];
        max_heap[cur] = max_heap[cur/2];
        max_heap[cur/2] = tmp;
        cur /= 2;
    }
}

void push_min(int v, int id) {
    min_heap[++min_size] = (node){v, id};

    int cur = min_size;

    while (cur > 1 && min_heap[cur].v < min_heap[cur/2].v) {
        node tmp = min_heap[cur];
        min_heap[cur] = min_heap[cur/2];
        min_heap[cur/2] = tmp;
        cur /= 2;
    }
}

void pop_max() {
    if (!max_size) return;
    max_heap[1] = max_heap[max_size--];
    int parent = 1;

    while (parent * 2 <= max_size) {
        int child = parent * 2;
        if (child + 1 <= max_size && max_heap[child + 1].v > max_heap[child].v) child++;
        if (max_heap[parent].v >= max_heap[child].v) break;

        node tmp = max_heap[parent];
        max_heap[parent] = max_heap[child];
        max_heap[child] = tmp;

        parent = child;
    }
}

void pop_min() {
    if (!min_size) return;
    min_heap[1] = min_heap[min_size--];
    int parent = 1;
    int child = parent * 2;

    while (parent * 2 <= min_size) {
        int child = parent * 2;
        if (child + 1 <= min_size && min_heap[child + 1].v < min_heap[child].v) child++;
        if (min_heap[parent].v <= min_heap[child].v) break;

        node tmp = min_heap[parent];
        min_heap[parent] = min_heap[child];
        min_heap[child] = tmp;

        parent = child;
    }
}

void clean_max() {
    while (max_size > 0 && is_deleted[max_heap[1].id]) {
        pop_max();
    }
}

void clean_min() {
    while (min_size > 0 && is_deleted[min_heap[1].id]) {
        pop_min();
    }
}

int main() {
    int t;
    scanf("%d", &t);

    while (t--) {
        int k;
        scanf("%d", &k);

        max_size = min_size = 0;

        for (int i = 0; i < k; i++) is_deleted[i] = 0;

        for (int i = 0; i < k; i++) {
            char op;
            int n;
            scanf(" %c %d", &op, &n);

            if (op == 'I') {
                push_max(n, i);
                push_min(n, i);
            } else {
                if (n == 1) {
                    clean_max();
                    if (max_size > 0) {
                        is_deleted[max_heap[1].id] = 1;
                        pop_max();
                    }
                } else {
                    clean_min();
                    if (min_size > 0) {
                        is_deleted[min_heap[1].id] = 1;
                        pop_min();
                    }
                }
            }
        }

        clean_max(); clean_min();

        if (!max_size || !min_size) puts("EMPTY");
        else printf("%d %d\n", max_heap[1].v, min_heap[1].v);
    }

    return 0;
}
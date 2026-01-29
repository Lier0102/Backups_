#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int weight;
    int price;
} Jewel;

int comp(const void *a, const void *b) {
    Jewel *j1 = (Jewel *)a;
    Jewel *j2 = (Jewel *)b;

    return j1->weight - j2->weight;
}

int comp2(const void *a, const void *b) {
    return *(int *)a - *(int *)b;
}

int heap[300001];
int size = 0;

void push(int v) {
    heap[++size] = v;
    int child = size;
    int parent = child / 2; //  (// 2)

    while (child > 1 && heap[parent] < heap[child]) {
        int tmp = heap[child];
        heap[child] = heap[parent];
        heap[parent] = tmp;

        child = parent;
        parent = child / 2;
    }
}

int pop() {
    int top = heap[1];
    heap[1] = heap[size--]; // size--;
    int parent = 1;
    int child = 2;

    while (child <= size) {
        if (child + 1 <= size && heap[child] < heap[child+1]) child++;
        if (heap[parent] >= heap[child]) break;

        int tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;

        parent = child;
        child = parent * 2;
    }

    return top;
}

int main() {
    int n, k;

    scanf("%d %d", &n, &k);

    Jewel *j = (Jewel *)malloc(sizeof(Jewel) * n);

    for (int i = 0; i < n; i++) {
        scanf("%d %d", &j[i].weight, &j[i].price);
    }

    int *b = (int *)malloc(sizeof(int) * k); // for bags

    for (int i = 0; i < k; i++) {
        scanf("%d", &b[i]);
    }

    qsort(j, n, sizeof(Jewel), comp);
    qsort(b, k, sizeof(int), comp2);

    long long result = 0;
    int idx = 0;

    for (int i = 0; i < k; i++) {
        while (idx < n &&  j[idx].weight <= b[i]) {
            push(j[idx].price);
            idx++;
        }

        if (size > 0) {
            result += pop();
        }
    }

    printf("%lld\n", result);

    free(j); free(b);

    return 0;
}
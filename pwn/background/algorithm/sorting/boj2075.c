#include <stdio.h>
#include <stdlib.h>

int heap[1501];
int size = 0;

void push(int v) {
    heap[++size] = v;
    int child = size;
    int parent = child / 2;
    
    while (child > 1 && heap[parent] > heap[child]) {
        int tmp = heap[child];
        heap[child] = heap[parent];
        heap[parent] = tmp;

        child = parent;
        parent = child / 2;
    }
}

int pop() {
    int top = heap[1];
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
    
    return top;
}

int main() {
    int n;

    scanf("%d", &n);

    for (int i = 0; i < n * n; i++) {
        int v;
        scanf("%d", &v);

        if (size < n) {
            push(v);
        } else {
            if(v > heap[1]) {
                pop();
                push(v);
            }
        }
    }

    printf("%d\n", heap[1]); // top 

    return 0;
}
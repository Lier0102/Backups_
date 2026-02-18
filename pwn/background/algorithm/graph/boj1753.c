// dijkstra
// D[ijk], str[a] lol

#include <stdio.h>
#include <stdlib.h>

#define INF 1e9

typedef struct {
    int to, w; // w for the weight;
} edge;

typedef struct edgenode{
    edge e;
    struct edgenode *next;
} edgenode;

typedef struct {
    int v, dist;
} node;

edgenode *graph[20001];
int dist[20001];
node heap[300001];
int size = 0; // heap_size

void push(int v, int d) {
    heap[++size] = (node){v, d};
    int cur = size;

    while (cur > 1 && heap[cur].dist < heap[cur / 2].dist) {
        node tmp = heap[cur];
        heap[cur] = heap[cur/2];
        heap[cur/2] = tmp;

        cur /= 2;
    }
}

node pop() {
    node res = heap[1];
    heap[1] = heap[size--];

    int cur = 1;
    while (cur * 2 <= size) {
        int child = cur * 2;
        if (child + 1 <= size && heap[child + 1].dist < heap[child].dist) child++;
        if (heap[cur].dist <= heap[child].dist) break;

        node tmp = heap[cur];
        heap[cur] = heap[child];
        heap[child] = tmp;

        cur = child;
    }

    return res;
}

void add_edge(int u, int v, int w) {
    edgenode *new = (edgenode *)malloc(sizeof(edgenode));
    new->e.to = v;
    new->e.w = w;
    new->next = graph[u];
    graph[u] = new;
}

int main() {
    int v, e, k;
    scanf("%d %d %d", &v, &e, &k);

    for (int i = 1; i <= v; i++) dist[i] = INF; // initialization

    for (int i = 0; i < e; i++) {
        int u, v, w;
        scanf("%d %d %d", &u, &v, &w);
        add_edge(u, v, w);
    }

    dist[k] = 0;
    push(k, 0);

    while (size > 0) {
        node cur = pop();
        if (cur.dist > dist[cur.v]) continue;

        for (edgenode *curr = graph[cur.v]; curr != NULL; curr = curr->next) {
            int nv = curr->e.to;
            int ndist = cur.dist + curr->e.w;
            if (ndist < dist[nv]) {
                dist[nv] = ndist;
                push(nv, ndist);
            }
        }
    }

    for (int i = 1; i <= v; i++) {
        if (dist[i] == INF) puts("INF");
        else printf("%d\n", dist[i]);
    }

    return 0;
}
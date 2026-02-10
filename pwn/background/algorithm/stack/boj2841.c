#include <stdio.h>

int stk[7][300001];
int top[7];

void init() {
    for (int i = 1; i <= 6; i++) {
        top[i] = -1;
    }
}

int empty(int idx) {
    return top[idx] == -1;
}

int peek(int idx) {
    return stk[idx][top[idx]];
}

void push(int idx, int v) {
    stk[idx][++top[idx]] = v;
}

void pop(int idx) {
    top[idx]--;
}

int main() {
    int n, p;
    int cnt = 0;
    scanf("%d %d", &n, &p);

    for (int i = 0; i < n; i++) {
        int a, b;
        scanf("%d %d", &a, &b);

        while (!empty(a) && peek(a) > b) {
            pop(a);
            cnt++;
        }
        
        if (empty(a) || peek(a) != b) {
            push(a, b);
            cnt++;
        }
    }

    printf("%d\n", cnt);

    return 0;
}
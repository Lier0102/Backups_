#include <stdio.h>

int stk[50001];
int top = -1;

int main() {
    int n;
    scanf("%d", &n);

    int cnt = 0;

    for (int i = 0; i < n; i++) {
        int x, y;
        scanf("%d %d", &x, &y);

        while (top >= 0 && stk[top] > y) {
            if (stk[top] > 0) {
                cnt++;
            }
            top--;
        }

        if (top == -1 || stk[top] < y) {
            if (y > 0) {
                stk[++top] = y;
            }
        }
    }

    while (top >= 0) {
        if (stk[top] > 0) {
            cnt++;
        }
        top--;
    }

    printf("%d\n", cnt);

    return 0;
}
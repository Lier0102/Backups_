#include <stdio.h>

char stk[500001];
char num[500001];
int top = -1;

int main() {
    int n, k;

    scanf("%d %d", &n, &k);
    scanf("%s", num);

    int kcx = k; // CX에서 따온 별칭 ㅋㅋ

    for (int i = 0; i < n; i++) {
        while (top != -1 && kcx > 0 && stk[top] < num[i]) {
            top--;
            kcx--;
        }
        stk[++top] = num[i];
    }

    top -= kcx; // don't need a 'if'

    for (int i = 0; i <= top; i++) {
        putchar(stk[i]);
    }

    return 0;
}
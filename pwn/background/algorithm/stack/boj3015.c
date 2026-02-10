#include <stdio.h>

typedef struct {
    long long height;
    long long cnt;
} P; // for the Pairs

P stk[500001];
int top = -1;

int main() {
    int n;
    long long res = 0;
    scanf("%d", &n);

    for (int i = 0; i < n; i++) {
        long long h;
        scanf("%lld", &h);

        long long C = 1;

        while (top >= 0 && stk[top].height < h) {
            res += stk[top].cnt;
            top--; // pop
        }

        if (top >= 0 && stk[top].height == h) {
            res += stk[top].cnt;
            C += stk[top].cnt;
            top--;

            if (top >= 0) {
                res += 1;
            }
        } else if (top >= 0) {
            res += 1;
        }

        top++;
        stk[top].height = h;
        stk[top].cnt = C;
    }

    printf("%lld", res);

    return 0;
}
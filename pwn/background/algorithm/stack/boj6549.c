#include <stdio.h>

typedef struct {
    int idx;
    int height;
} Node;

Node stk[100001];
int top; // 0

int main() {
    int n;
    // top = -1;
    
    while (1) {
        scanf("%d", &n);

        if (!n) break;
        long long max = 0;
        top = -1;

        for (int i = 0; i <= n; i++) { // suppose that there is imaginary data(0)
            long long h;

            if (i < n) scanf("%lld", &h);
            else h = 0; // imaginary

            while (top != -1 && stk[top].height > h) {
                Node target = stk[top--];
                long long width;

                if (top == -1) {
                    width = i;
                } else {
                    width = i - stk[top].idx - 1;
                }

                long long cur = target.height * width;
                if (cur > max) max = cur;
            }

            stk[++top].idx = i;
            stk[top].height = h;
        }

        printf("%lld\n", max);
    }

    return 0;
}
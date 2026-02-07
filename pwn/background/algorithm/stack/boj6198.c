#include <stdio.h>

int stk[80001];
int top = -1;

int main() {
    int n;
    long long cnt = 0; // n + .... n * (n - 1) / 2

    scanf("%d", &n);

    while (n--) {
        int h;
        scanf("%d", &h);

        while (top != -1 && stk[top] <= h) {
            top--;
        }

        cnt += (top + 1); // top starts from -1, 

        stk[++top] = h;
    }

    printf("%lld", cnt); // res

    return 0;
}
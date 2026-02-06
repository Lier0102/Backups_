#include <stdio.h>

// 10(10) to 10(2)
// =
// 10 mod 2 -> 0
// 5 mod 2 -> 1
// 2 mod 2 -> 0
// 1 mod 2 -> 1
// 1010(2)
// stack is the best...perhaps;

int main() {
    int n, b;
    char stk[101];
    int top = -1;

    scanf("%d %d", &n, &b);

    while (n > 0) {
        int r = n % b;

        if (r < 10) {
            stk[++top] = r + '0';
        } else {
            stk[++top] = (r - 10) + 'A';
        }

        n /= b;
    }

    while (top != -1) {
        putchar(stk[top--]);
    }
    // else;;;; nuh uh


    return 0;
}